#include "Application.hh"
#include "Loader.hh"
#include "HostManager.hh"
#include "types/ethaddr.hh"

struct host_info {
    host_info(std::string, std::string, uint32_t, uint64_t);
    host_info();
    std::string mac;
    std::string ip;
    uint32_t switch_port;
    uint64_t switch_id;
};


struct ports {
    ports();
    std::set<uint32_t> trusted;
    std::set<uint32_t> user;
    std::set<uint32_t> ambiguous;
    std::set<uint32_t> infected;
};


struct score{
    score();
    host_info host;
    std::string type;
    float prev_counter;
    float curr_counter;
    float good_flows;
    float all_flows;
    float crit;
    float prev_score;
};


struct counters{
    counters();
    int curr_counter;
    int prev_counter;
};

//for testing
/*struct flow_stat{
    flow_stat();
    int inf_count;
    int usr_count;
    bool done;
};*/

class DDoS_Defender : public Application {
    Q_OBJECT
    SIMPLE_APPLICATION(DDoS_Defender, "DDoS_Defender")
private:
    bool ATTACK;
    bool BuildDone;
    static int THRESHOLD;
    static int crit_good_flows;
    static float alpha;
    static int interval;
    //bool test_interval; //for testing

    SwitchManager* sm;
    OFTransaction *oftran;
    std::vector<host_info> hosts;
    std::unordered_map<std::string, host_info> RevIPBindTable;
    std::unordered_map<std::string, host_info> IPBindTable;
    std::unordered_map<uint64_t, ports> switches;
    std::unordered_map<uint64_t, uint32_t> drop_ports;
    std::unordered_map<std::string, score> src_criterion;
    std::unordered_map<std::string, counters> attack_end;
    std::map<uint64_t, bool> sw_response;

    //std::unordered_map<uint64_t,flow_stat> switch_flow_test; //for testing

    void add_to_RevTable(std::string, std::string, uint32_t, uint64_t);

    void check_RevTable();

    void build_IPBindTable();
    void build_ports_set();

    void get_cpu_util();

    void config_drop_ports_no();
    void init_drop_ports();


    void timerEvent(QTimerEvent*) override;

    void get_flow_stats();
    void print_flow_stats(std::vector<of13::FlowStats>);

    void send_init_flowmods();
    void send_drop_flowmod(uint64_t, uint32_t);

    //for testing
    //void add_flow_statistic_from_switch(std::vector<of13::FlowStats>, uint64_t);
    //void print_flow_test();

    void add_src_statistic_from_switch(std::vector<of13::FlowStats>, uint64_t);
    void init_src_criterion();
    void check_src_criterion(uint64_t);
    void check_attack_end();

public:
    static float threshold_low;
    static float threshold_hight;
    static double cpu_util;
    static double threshold_cpu_util;

    void print_ip_table();
    void print_rev_ip_table();
    void print_hosts();
    void print_ports();
    void print_drop_ports();
    void print_src_criterion();
    void print_attack_end();
    void init(Loader*, const Config&) override;
    void startUp(Loader*);
signals:
    void new_port(SwitchConnectionPtr ofconn, of13::PortStatus ps);
};
