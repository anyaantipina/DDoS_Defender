#include "Controller.hh"
#include "SwitchConnection.hh"
#include "Switch.hh"
#include "Common.hh"
#include "DDoS_Defender.hh"

#include <algorithm>
#include <unistd.h>
#include <sys/types.h>
#include "sys/times.h"
#include "sys/vtimes.h"

#include "oxm/openflow_basic.hh"
#include "oxm/field_set.hh"
#include <boost/lexical_cast.hpp>
#include "api/TraceablePacket.hh"
#include "FluidOXMAdapter.hh"
#include "types/IPv4Addr.hh"

REGISTER_APPLICATION(DDoS_Defender, {"controller", "host-manager", ""})

typedef of13::OXMTLV* ModifyElem;
typedef std::vector<ModifyElem> ModifyList;

//FOR TREE TOPOLOGY
int DDoS_Defender::crit_good_flows = 3;
float DDoS_Defender::alpha = 0.4;
float DDoS_Defender::threshold_low = 0.25;
float DDoS_Defender::threshold_hight = 0.4;
int DDoS_Defender::THRESHOLD = 20;
double DDoS_Defender::cpu_util = 0.0;
int DDoS_Defender::interval = 3;
double DDoS_Defender::threshold_cpu_util = 25;


static clock_t lastCPU, lastSysCPU, lastUserCPU;

std::string convert_ip_addr(std::string ip){
    std::vector<std::string> fragms;
    std::string fragm = "";
    for (char c : ip){
        if (c == '.'){
            fragms.push_back(fragm);
            fragm = "";
        }
        else {
            fragm += c;
        }
    }
    fragms.push_back(fragm);
    return fragms[3] + '.' + fragms[2] + '.' + fragms[1] + '.' + fragms[0];
}

void init_cpu_util(){
    struct tms timeSample;

    lastCPU = times(&timeSample);
    lastSysCPU = timeSample.tms_stime;
    lastUserCPU = timeSample.tms_utime;
}

void DDoS_Defender::get_cpu_util(){
    struct tms timeSample;
    clock_t now;
    double percent;

    now = times(&timeSample);
    if (now <= lastCPU || timeSample.tms_stime < lastSysCPU ||
        timeSample.tms_utime < lastUserCPU){
        percent = -1.0;
    }
    else{
        percent = (timeSample.tms_stime - lastSysCPU) + (timeSample.tms_utime - lastUserCPU);
        percent /= (now - lastCPU);
        percent *= 100;
    }
    lastCPU = now;
    lastSysCPU = timeSample.tms_stime;
    lastUserCPU = timeSample.tms_utime;

    cpu_util = percent;
}


float string_to_float(std::string s) {
    std::string::size_type pos = s.rfind(".");
    std::string x1 = s.substr(0, pos);
    std::string x2 = s.substr(pos+1, s.length()-pos-1);
    int y1 = 0;
    int y2 = 0;
    if (x1.length() != 0) {
        y1 = stoi(x1);
    }
    if (x2.length() != 0) {
        y2 = stoi(x2);
    }
    return (y1+y2*pow(0.1,x2.length()));
}

void DDoS_Defender::init(Loader *loader, const Config &rootConfig){

    init_cpu_util();

    auto config = config_cd(rootConfig, "DDoS_Defender");
    crit_good_flows = config_get(config, "crit_good_flows", 3);
    alpha = string_to_float(config_get(config, "alpha", "0.4").c_str());
    threshold_low = string_to_float(config_get(config, "threshold_low", "0.1").c_str());
    threshold_hight = string_to_float(config_get(config, "threshold_hight", "0.4").c_str());
    THRESHOLD = config_get(config, "THRESHOLD",20);
    interval = config_get(config, "interval", 3);

    //test_interval = false; //FOR TESTING


    BuildDone = false;
    ATTACK = false;
    Controller *ctrl = Controller::get(loader);
    HostManager *hm = HostManager::get(loader);
    sm = SwitchManager::get(loader);

    //ADD HOSTS
    QObject::connect(hm, &HostManager::hostDiscovered, [this](Host* dev){
        host_info host(dev->mac(), dev->ip(), dev->switchPort(), dev->switchID());
        hosts.push_back(host);
    });

    //RESPONSE TO FLOW STATS REPLY
    oftran = ctrl->registerStaticTransaction(this);
    QObject::connect(oftran, &OFTransaction::response,
          [this](SwitchConnectionPtr conn, std::shared_ptr<OFMsgUnion> reply){
        uint64_t sw_id = conn->dpid();
        OFMsg* basereply = reply->base();
        of13::MultipartReply* mpreply = (of13::MultipartReply*)basereply;
        std::vector<of13::FlowStats> flow_stats =
                ((of13::MultipartReplyFlow*)mpreply)->flow_stats();

        //FOR TESTING
        /*if (!test_interval) {
            add_flow_statistic_from_switch(flow_stats, sw_id);
            bool done = true;
            for (auto it : switch_flow_test){
                if (!it.second.done) {
                    done = false;
                    break;
                }
            }
            if (done) {
                test_interval = true;
            }
        }
        else {
            print_flow_test();
            test_interval = false;
        }*/

        add_src_statistic_from_switch(flow_stats, sw_id);

        bool is_filled = true;
        sw_response[sw_id] = true;
        for (auto it : sw_response)
            if (it.second == false) {
                is_filled = false;
            }

        if (ATTACK) {
            check_src_criterion(sw_id);
            if (is_filled == true) {
                check_attack_end();
            }
            //print_attack_end();
        }
    });
    ctrl->registerHandler("MyHandler",[this](SwitchConnectionPtr conn) {

        const auto ofb_eth_type = oxm::eth_type(); // for optimization
        const auto ofb_ipv4_src = oxm::ipv4_src();
        const auto ofb_eth_src = oxm::eth_src();
        const auto ofb_in_port = oxm::in_port();
        const auto ofb_arp_spa = oxm::arp_spa();

        return [=](Packet& pkt, FlowPtr, Decision decision) {
            auto tpkt = packet_cast<TraceablePacket>(pkt);

            IPAddress src_ip("0.0.0.0");
            ethaddr src_mac = pkt.load(ofb_eth_src);
            uint32_t port_no = tpkt.watch(ofb_in_port);
            uint64_t sw_id = conn->dpid();
            if (pkt.test(ofb_eth_type == 0x0800)) {
                IPv4Addr ipv4_src = tpkt.watch(ofb_ipv4_src);
                src_ip = IPAddress(ipv4_src.to_number());
            } else if (pkt.test(ofb_eth_type == 0x0806)) {
                src_ip = IPAddress(tpkt.watch(ofb_arp_spa));
                std::string str_ip = AppObject::uint32_t_ip_to_string(src_ip.getIPv4());
            }
            std::string str_mac = boost::lexical_cast<std::string>(src_mac);
            std::string str_ip = AppObject::uint32_t_ip_to_string(src_ip.getIPv4());
            std::string config_ip_src = convert_ip_addr(str_ip);

            if (!BuildDone) { // BUILDING IP_BIND_TABLE
                add_to_RevTable(str_mac, config_ip_src, port_no, sw_id);
            }
            else { // INCREASING SRC PACKET_IN COUNTER
                std::string key = "MAC " + str_mac + " IP " + config_ip_src;
                auto it_find = src_criterion.find(key);
                if (it_find != src_criterion.end()){
                    src_criterion[key].curr_counter += 1;
                    attack_end[key].curr_counter += 1;
                    if ((src_criterion[key].curr_counter > THRESHOLD)
                            and (ATTACK == false)) {
                        LOG(INFO) << "TOO MANY PACKET_IN FROM " << key;
                        LOG(INFO) << "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
                        ATTACK = true;
                    }
                }
            }
            return decision;
        };
    });
}

void DDoS_Defender::startUp(Loader* ) {
            LOG(INFO) << "All services inited";
            startTimer(interval*1000);
}


void DDoS_Defender::timerEvent(QTimerEvent*) {
    if (BuildDone){
        get_cpu_util();
        get_flow_stats();
    }
}

void DDoS_Defender::add_to_RevTable(std::string mac, std::string ip, uint32_t port_no, uint64_t sw_id){
    std::string key = "switch_id " + std::to_string(sw_id) +
            " port_no " + std::to_string(port_no);
    auto find_key = RevIPBindTable.find(key);
    if (find_key == RevIPBindTable.end()){
        host_info host(mac, ip, port_no, sw_id);
        RevIPBindTable.insert({key,host});
        check_RevTable();
    }
    else {
        if ((find_key->second.ip == "0.0.0.0") and (ip != "0.0.0.0")) {
        host_info host(mac, ip, port_no, sw_id);
        RevIPBindTable[key] = host;
        int index = 0;
        for (auto it_hosts : hosts){
            if ((it_hosts.ip == "0.0.0.0") and  (it_hosts.mac == mac)) {
                hosts[index] = host;
                break;
            }
            index++;
        }
        check_RevTable();
        }
    }
}

void DDoS_Defender::get_flow_stats(){
    for (auto it : switches){
        Switch* sw = sm->getSwitch(it.first);
        of13::MultipartRequestFlow mprf;
        mprf.table_id(of13::OFPTT_ALL);
        mprf.out_port(of13::OFPP_ANY);
        mprf.out_group(of13::OFPG_ANY);
        mprf.cookie(0x0);
        mprf.cookie_mask(0x0);
        mprf.flags(0);
        oftran->request(sw->connection(),  mprf);
    }
    bool is_filled = true;
    for (auto it : sw_response) {
        if (it.second == false) {
            is_filled = false;
            break;
        }
    }
    if (is_filled == true){
        for (auto it = sw_response.begin(); it != sw_response.end(); it++) {
            it->second = false;
        }
    }
}

struct FlowDescImpl {
    uint32_t in_port{0};
    uint32_t out_port{0};
    uint16_t eth_type{0};
    EthAddress eth_src{};
    EthAddress eth_dst{};
    IPAddress ip_src{};
    IPAddress ip_dst{};

    int idle{0};
    int hard{0};
    uint16_t priority{0};

    ModifyList modify;
};

void DDoS_Defender::send_init_flowmods(){
    const auto ofb_in_port = oxm::in_port();
    const auto ofb_eth_type = oxm::eth_type();
    const auto ofb_ipv4_src = oxm::ipv4_src();
    const auto ofb_eth_src = oxm::eth_src();

    for (auto it_switch : switches){
        Switch* switch_ = sm->getSwitch(it_switch.first);

        //DROP ACTIONS
        for (auto host_port : it_switch.second.user){
            uint16_t priority = 0;
            priority += host_port;
            oxm::field_set m_match1, m_match2;
            m_match1.modify(ofb_in_port == host_port);
            m_match1.modify(ofb_eth_type == 0x0800);
            m_match2.modify(ofb_in_port == host_port);
            m_match2.modify(ofb_eth_type == 0x0806);

            of13::FlowMod fm1, fm2;
            fm1.command(of13::OFPFC_ADD); fm2.command(of13::OFPFC_ADD);
            fm1.xid(0); fm2.xid(0);
            fm1.buffer_id(OFP_NO_BUFFER); fm2.buffer_id(OFP_NO_BUFFER);
            fm1.table_id(0); fm2.table_id(0);
            fm1.priority(priority); fm2.priority(priority);
            fm1.cookie(0x0); fm2.cookie(0x0);
            fm1.idle_timeout(0); fm2.idle_timeout(0);
            fm1.hard_timeout(0); fm2.hard_timeout(0);
            fm1.flags( of13::OFPFF_CHECK_OVERLAP | of13::OFPFF_SEND_FLOW_REM );
            fm2.flags( of13::OFPFF_CHECK_OVERLAP | of13::OFPFF_SEND_FLOW_REM );
            fm1.match(make_of_match(m_match1)); fm2.match(make_of_match(m_match2));
            switch_->connection()->send(fm1);
            switch_->connection()->send(fm2);
        }

        //GOTOTABLE ACTIONS FOR TRUSTED PORTS
        for (auto trust_port : it_switch.second.trusted){
            oxm::field_set m_match;
            m_match.modify(ofb_in_port == trust_port);

            of13::FlowMod fm;
            fm.command(of13::OFPFC_ADD);;
            fm.xid(0);
            fm.buffer_id(OFP_NO_BUFFER);
            fm.table_id(0);
            fm.priority(1);
            fm.cookie(0x0);
            fm.idle_timeout(0);
            fm.hard_timeout(0);
            fm.flags( of13::OFPFF_CHECK_OVERLAP | of13::OFPFF_SEND_FLOW_REM );
            fm.match(make_of_match(m_match));
            of13::GoToTable go_to_table(1);
            fm.add_instruction(go_to_table);
            switch_->connection()->send(fm);
        }
    }

    //GOTOTABLE ACTIONS
    for (auto it_BindTable : IPBindTable) {
        Switch* switch_ = sm->getSwitch(it_BindTable.second.switch_id);
        ethaddr eth_src(it_BindTable.second.mac);
        //IPv4Addr ipv4_src(it_BindTable.second.ip);
        uint16_t priority = 20;
        priority += it_BindTable.second.switch_port;

        oxm::field_set m_match1, m_match2;
        m_match1.modify(ofb_in_port == it_BindTable.second.switch_port);
        m_match1.modify(ofb_eth_type == 0x0800);
        m_match1.modify(ofb_eth_src == eth_src);
        m_match1.modify(ofb_ipv4_src == it_BindTable.second.ip);
        m_match2.modify(ofb_in_port == it_BindTable.second.switch_port);
        m_match2.modify(ofb_eth_type == 0x0806);
        m_match2.modify(ofb_eth_src == eth_src);

        of13::FlowMod fm1, fm2;
        fm1.command(of13::OFPFC_ADD); fm2.command(of13::OFPFC_ADD);
        fm1.xid(0); fm2.xid(0);
        fm1.buffer_id(OFP_NO_BUFFER); fm2.buffer_id(OFP_NO_BUFFER);
        fm1.table_id(0); fm2.table_id(0);
        fm1.priority(priority); fm2.priority(priority);
        fm1.cookie(0x0); fm2.cookie(0x0);
        fm1.idle_timeout(0); fm2.idle_timeout(0);
        fm1.hard_timeout(0); fm2.hard_timeout(0);
        fm1.flags( of13::OFPFF_CHECK_OVERLAP | of13::OFPFF_SEND_FLOW_REM );
        fm2.flags( of13::OFPFF_CHECK_OVERLAP | of13::OFPFF_SEND_FLOW_REM );
        fm1.match(make_of_match(m_match1)); fm2.match(make_of_match(m_match2));
        of13::GoToTable go_to_table(1);
        fm1.add_instruction(go_to_table);
        fm2.add_instruction(go_to_table);
        switch_->connection()->send(fm1);
        switch_->connection()->send(fm2);
    }
}

void DDoS_Defender::send_drop_flowmod(uint64_t sw_id, uint32_t port_no){
    const auto ofb_in_port = oxm::in_port();
    const auto ofb_eth_type = oxm::eth_type();
    Switch* sw = sm->getSwitch(sw_id);
    oxm::field_set m_match1, m_match2;
    m_match1.modify(ofb_in_port == port_no);
    m_match1.modify(ofb_eth_type == 0x0800);
    m_match2.modify(ofb_in_port == port_no);
    m_match2.modify(ofb_eth_type == 0x0806);

    of13::FlowMod fm1, fm2;
    fm1.command(of13::OFPFC_ADD); fm2.command(of13::OFPFC_ADD);
    fm1.xid(0); fm2.xid(0);
    fm1.buffer_id(OFP_NO_BUFFER); fm2.buffer_id(OFP_NO_BUFFER);
    fm1.table_id(0); fm2.table_id(0);
    fm1.priority(40); fm2.priority(40);
    fm1.cookie(0x0); fm2.cookie(0x0);
    fm1.idle_timeout(0); fm2.idle_timeout(0);
    fm1.hard_timeout(0); fm2.hard_timeout(0);
    fm1.flags( of13::OFPFF_CHECK_OVERLAP | of13::OFPFF_SEND_FLOW_REM );
    fm2.flags( of13::OFPFF_CHECK_OVERLAP | of13::OFPFF_SEND_FLOW_REM );
    fm1.match(make_of_match(m_match1)); fm2.match(make_of_match(m_match2));
    sw->connection()->send(fm1);
    sw->connection()->send(fm2);
}

//INIT FUNCTIONS

void DDoS_Defender::init_src_criterion(){
    for (auto it : IPBindTable){
        score elem_score;
        elem_score.host = it.second;
        src_criterion.insert({it.first,elem_score});
        counters elem;
        attack_end.insert({it.first,elem});
    }
}

//CHECKING FUNCTIONS

void DDoS_Defender::check_RevTable(){
    bool done = true;
    if (hosts.size() == 0) done = false;
    for (auto it : hosts){
        if (it.ip == "0.0.0.0") {
            done = false;
        }
    }
    if (done) {
        build_IPBindTable();
        build_ports_set();
        print_ip_table();
        print_ports();
        init_src_criterion();
        //get_flow_stats();
        send_init_flowmods();
        BuildDone = true;
    }
}


//BUILDING FUNCTIONS
void DDoS_Defender::build_IPBindTable(){
    for (auto it_rev_table : RevIPBindTable) {
        for (auto it_hosts : hosts){
            if (it_hosts.ip == it_rev_table.second.ip) {
                host_info host(it_hosts.mac, it_hosts.ip, it_hosts.switch_port, it_hosts.switch_id);
                std::string key = "MAC " + it_hosts.mac + " IP " + it_hosts.ip;
                IPBindTable.insert({key, host});
                //score s;
                //s.host = *it_hosts;
                //src_criterion.insert({it_rev_table->first, s});
                break;
            }
        }
    }
    RevIPBindTable.clear();
}

void DDoS_Defender::build_ports_set(){
    std::set<uint64_t> switches_set;
    for (auto it_ip_table : IPBindTable){
        auto find_switch = switches_set.find(it_ip_table.second.switch_id);
        if (find_switch != switches_set.end()) {
            switches[*find_switch].user.insert(it_ip_table.second.switch_port);
        }
        else {
            ports elem;
            elem.user.insert(it_ip_table.second.switch_port);
            switches.insert({it_ip_table.second.switch_id, elem});
            sw_response.insert({it_ip_table.second.switch_id, false});
            //flow_stat elem2; //for testing
            //switch_flow_test.insert({it_ip_table.second.switch_id, elem2}); //for testing
            switches_set.insert(it_ip_table.second.switch_id);
        }
    }
    for (auto it_switch_set : switches){
        Switch* sw = sm->getSwitch(it_switch_set.first);
        std::vector<of13::Port> ports = sw->ports();
        for (auto it_ports : ports){
            if (switches[it_switch_set.first].user.find(it_ports.port_no()) ==
                    switches[it_switch_set.first].user.end()) {
                switches[it_switch_set.first].trusted.insert(it_ports.port_no());
            }
        }
    }
    switches_set.clear();
}

//PRINTING FUNCTIONS

void DDoS_Defender::print_hosts(){
    LOG(INFO) << "hosts (size = " << hosts.size() <<") :";
    for (auto it : hosts){
        LOG(INFO) << "IP: " << it.ip << " MAC: " << it.mac;
    }
}

void DDoS_Defender::print_rev_ip_table(){
    LOG(INFO) << "RevIPBindTable (size = " << RevIPBindTable.size() <<") :";
    for (auto it : RevIPBindTable){
        LOG(INFO) << "IP: " << it.second.ip << " MAC: " << it.second.mac << " " << it.first;
    }
}

void DDoS_Defender::print_ip_table(){
    LOG(INFO) << "IPBindTable (size = " << IPBindTable.size() <<") :";
    for (auto it : IPBindTable){
        LOG(INFO) << it.first << ", sw_id: " << it.second.switch_id
                  << ", port_no " << it.second.switch_port;
    }
}

void DDoS_Defender::print_ports(){
    LOG(INFO) << "Switches and port's set (size = " << switches.size() <<") :";
    for (auto it_sw_id : switches){
        std::string trust = "";
        for (auto it_t_p : it_sw_id.second.trusted){
            trust += std::to_string(it_t_p) + " ";
        }
        std::string user = "";
        for (auto it_h_p : it_sw_id.second.user){
            user += std::to_string(it_h_p) + " ";
        }
        std::string ambig = "";
        for (auto it_a_p : it_sw_id.second.ambiguous){
            ambig += std::to_string(it_a_p) + " ";
        }
        std::string infect = "";
        for (auto it_i_p : it_sw_id.second.infected){
            infect += std::to_string(it_i_p) + " ";
        }

        LOG(INFO) << "switch id " << it_sw_id.first << ", trusted ports: " << trust
                  << ", user ports: " << user
                  << ", ambiguous ports: " << ambig
                  << ", infected ports: " << infect;
    }
}

//FOR TESTING

/*void DDoS_Defender::print_flow_test(){
    LOG(INFO) << "Switches flow test (size = " << switch_flow_test.size() <<") :";
    for (auto it : switch_flow_test){
        LOG(INFO) << "switch id " << it.first << ", infected flows count: " << it.second.inf_count
                  << ", user flows count: " << it.second.usr_count
                  << ", done: " << it.second.done;
    }
}*/

void DDoS_Defender::print_flow_stats(std::vector<of13::FlowStats> flow_stats){
    int index = 0;
    for (auto it : flow_stats){
        of13::FlowStats *flow1 = static_cast<of13::FlowStats *>(&it);
        of13::Match match = flow1->match();
        std::string mac, ip;
        if (match.eth_src())
            mac = match.eth_src()->value().to_string();
        else continue;
        if (match.ipv4_src()) {
            ip = AppObject::uint32_t_ip_to_string(match.ipv4_src()->value().getIPv4());
        }
        LOG(INFO) << "flow " << index << " MAC " << mac << " IP " << ip
                  << ", table id: " << unsigned(it.table_id())
                  << "idle_to: " << it.idle_timeout()
                  << ", hard_to: " << it.hard_timeout()
                  << ", packet count: " << it.packet_count();
        index++;
    }
}

void DDoS_Defender::print_src_criterion(){
    LOG(INFO) << "Src_criterion (size = " << src_criterion.size() <<") :";
    for (auto it : src_criterion){
        LOG(INFO) << it.first << " type " << it.second.type
                  << " packet_in_counter (prev = " << it.second.prev_counter
                  << ", curr = " << it.second.curr_counter << "), "
                  << " crit " << it.second.crit
                  << " score " << it.second.prev_score;
    }
}

void DDoS_Defender::print_attack_end(){
    LOG(INFO) << "Attack_end (size = " << src_criterion.size() <<") :";
    for (auto it : attack_end){
        LOG(INFO) << it.first << " prev_counter " << it.second.prev_counter << " curr_counter " << it.second.curr_counter;
    }
}

//HOST-INFO STRUCTURE
host_info::host_info(std::string mac, std::string ip, uint32_t switch_port, uint64_t switch_id){
    this->ip = ip;
    this->mac = mac;
    this->switch_port = switch_port;
    this->switch_id = switch_id;
}
host_info::host_info(){
    this->ip = "";
    this->mac = "";
    this->switch_port = 0;
    this->switch_id = 0;
}

//PORT CLASSIFICATION STRUCTURE
ports::ports() {
    this->trusted = {};
    this->user = {};
    this->ambiguous = {};
    this->infected = {};
}

//HOST'S SCORE STRUCTURE
score::score(){
    this->type = "USER";
    this->prev_counter = 1;
    this->curr_counter = 1;
    this->good_flows = 1;
    this->all_flows = 1;
    this->crit = DDoS_Defender::threshold_hight;
    this->prev_score = DDoS_Defender::threshold_hight;
}

counters::counters(){
    this->curr_counter = 0;
    this->prev_counter = 0;
}

//FOR TESTING

/*flow_stat::flow_stat(){
    this->inf_count=0;
    this->usr_count=0;
    this->done = false;
}

void DDoS_Defender::add_flow_statistic_from_switch(std::vector<of13::FlowStats> flow_stats, uint64_t sw_id){
    switch_flow_test[sw_id].inf_count = 0;
    switch_flow_test[sw_id].usr_count = 0;
    for (auto it : flow_stats){
        of13::FlowStats *flow1 = static_cast<of13::FlowStats *>(&it);
        of13::Match match = flow1->match();
        std::string mac, ip;
        if (match.eth_src())
            mac = match.eth_src()->value().to_string();
        for (auto it : src_criterion) {
            if (it.second.host.mac == mac) {
                if (it.second.type == "INFECTED")
                    switch_flow_test[sw_id].inf_count+=1;
                else if (it.second.type == "USER")
                    switch_flow_test[sw_id].usr_count+=1;
            }
        }
    }
    switch_flow_test[sw_id].done = true;
}*/



//FOR SRC CRITERION

void DDoS_Defender::add_src_statistic_from_switch(std::vector<of13::FlowStats> flow_stats, uint64_t sw_id){
    //CLEAN OLD STATISTIC
    for (auto it_src_crit : src_criterion){
        if (src_criterion[it_src_crit.first].host.switch_id == sw_id) {
            src_criterion[it_src_crit.first].all_flows = 1;
            src_criterion[it_src_crit.first].good_flows = 1;
            src_criterion[it_src_crit.first].prev_counter = src_criterion[it_src_crit.first].curr_counter;
            src_criterion[it_src_crit.first].curr_counter = 1;
            attack_end[it_src_crit.first].prev_counter=src_criterion[it_src_crit.first].prev_counter;
            attack_end[it_src_crit.first].curr_counter=src_criterion[it_src_crit.first].curr_counter;
        }
    }
    //ADD NEW STATISTIC
    for (auto it : flow_stats){
        of13::FlowStats *flow1 = static_cast<of13::FlowStats *>(&it);
        of13::Match match = flow1->match();
        std::string mac, ip;
        if (match.eth_src())
            mac = match.eth_src()->value().to_string();
        if (match.ipv4_src()) {
            ip = AppObject::uint32_t_ip_to_string(match.ipv4_src()->value().getIPv4());
        }
        std::string key = "MAC " + mac + " IP " + ip;
        if (src_criterion.find(key) != src_criterion.end()){
            src_criterion[key].all_flows += 1;
            if (it.packet_count() > unsigned(crit_good_flows)){
                src_criterion[key].good_flows += 1;
            }
        }
    }
}

void DDoS_Defender::check_src_criterion(uint64_t sw_id){
    for (auto it : src_criterion){
        if (src_criterion[it.first].host.switch_id == sw_id) {
             std::string key = it.first;
            if (src_criterion[key].type == "INFECTED"){
                continue;
            }
            if (src_criterion[key].all_flows != 0) {
                src_criterion[key].crit = src_criterion[key].good_flows / src_criterion[key].all_flows;
            }
            else {
                src_criterion[key].crit = threshold_hight;
            }
            float curr_score;
            if (src_criterion[key].prev_counter != 0) {
                curr_score = src_criterion[key].crit / src_criterion[key].prev_counter;
            }
            else {
                curr_score = threshold_hight;
            }
            curr_score = (1 - alpha) * curr_score + alpha*it.second.prev_score;
            src_criterion[key].prev_score = curr_score;
            if ((curr_score < threshold_low)) {
                LOG(INFO) << key << " modif_curr_score " << curr_score << " INFECTED";
                //DELETE FROM USER GROUP AND ADD TO INFECTED
                if (src_criterion[key].type == "USER") {
                    switches[it.second.host.switch_id].user.erase(it.second.host.switch_port);
                }
                else if (src_criterion[key].type == "AMBIGUOUS") {
                    switches[it.second.host.switch_id].ambiguous.erase(it.second.host.switch_port);
                }
                switches[it.second.host.switch_id].infected.insert(it.second.host.switch_port);
                src_criterion[key].type = "INFECTED";
                //DROP PACKETS FROM SRC
                send_drop_flowmod(it.second.host.switch_id, it.second.host.switch_port);
            }
            else if ((curr_score < threshold_hight)
                    && (src_criterion[key].type != "AMBIGUOUS")) {
                //DELETE FROM USER GROUP
                if (src_criterion[key].type == "USER") {
                    switches[it.second.host.switch_id].user.erase(it.second.host.switch_port);
                }
                if (cpu_util > threshold_cpu_util) {
                    LOG(INFO) << key << " modif_curr_score " << curr_score << " INFECTED";
                    if (src_criterion[key].type == "AMBIGUOUS") {
                        switches[it.second.host.switch_id].ambiguous.erase(it.second.host.switch_port);
                    }
                    //ADD TO INFECTED
                    src_criterion[key].type = "INFECTED";
                    switches[it.second.host.switch_id].infected.insert(it.second.host.switch_port);
                    //DROP PACKETS FROM SRC
                    send_drop_flowmod(it.second.host.switch_id, it.second.host.switch_port);
                }
                else {
                    LOG(INFO) << key << " modif_curr_score " << curr_score << " AMBIGUOUS";
                    //ADD TO AMBIGUOUS
                    switches[it.second.host.switch_id].ambiguous.insert(it.second.host.switch_port);
                    src_criterion[key].type = "AMBIGUOUS";
                }
            }
            else if ((curr_score >= threshold_hight)
                     && (src_criterion[key].type != "USER")) {
                LOG(INFO) << key << " modif_curr_score " << curr_score << " USER";
                //DELETE FROM ANBIGUOUS GROUP AND ADD TO USER
                switches[it.second.host.switch_id].ambiguous.erase(it.second.host.switch_port);
                switches[it.second.host.switch_id].user.insert(it.second.host.switch_port);
                src_criterion[key].type = "USER";
            }
        }
    }
    //print_src_criterion();
}

void DDoS_Defender::check_attack_end(){
    bool end=true;
    for (auto it : attack_end){
        if ((it.second.curr_counter > THRESHOLD) || (it.second.prev_counter > THRESHOLD)) {
            end = false;
            break;
        }
    }
    if (end) {
        ATTACK = false;
        LOG(INFO) << "END OF THE ATTACK";
        print_ports();
    }
}
