# DDoS_Defender
Для установки и запуска DDoS_Defender необходимо скачать исходный код приложения 
из репозитория https://github.com/anyaantipina/DDoS_Defender и скопировать файлы 
DDoS_Defender.cpp и DDoS_Defender.h в директорию runos/src.

В файле CMakeLists.txt директории runos/src добавить «DDoS_Defender.cpp» в список SOURCES.

В конфигурационном файле network-settings.json необходимо указать «DDoS_Defender» в списке «services»: [], 
добавить функцию-обработчик «MyHandler» в список «controller»: «pipeline»: [] и 
добавить следующую структуру с указанием нужных величин, например, таких (пример конфигурационного файла
хранится в корневой директории):

"DDoS_Defender" : {
  "crit_good_flows" : 3,
  "alpha" : "0.2",
  "threshold_low" : "0.19",
  "threshold_hight" : "0.9",
  "threshold_cpu_util" : “40”,
  "THRESHOLD" : 100,
  "interval" : 3,
  "hosts_amount" : 8
}

Перед первым запуском контроллера необходимо выполнять команду «source ../debug_run_env.sh».

Сценарий работы сети с проведением атаки. 
Для эмуляции работы сети и проведения атаки написаны два вида скриптов:
  – для пользовательских хостов (usr.sh) в папке "to build IPBindTable"
  - для зараженных хостов (atck.sh) в папке "for attack". 
После запуска контроллера и сети необходимо запустить на пользовательских хостах команду «./usr N», где N – номер хоста
(N = 1, 10, 20, 30 и тд на каждом 10-м хосте). Ping всех хостов необходим для построения IPBindTable.
На зараженных хостах необходимо запустить следующую команду (в зависимости от условий запуска контроллера):
  1) При запуске контроллера без DDoS_Defender – «./atck N %», где N – номер хоста, 
    а «%» гарантирует генерацию пакетов с различными MAC и IP адресами источника и получателя.
  2) При запуске контроллера с DDoS_Defender – «./atck N MAC», где N – номер хоста, 
    MAC – MAC адрес хоста (его можно узнать из LOG(INFO) после вывода посроенной IPBindTable. 
    Необходимо указывать MAC адрес хоста, так как чтобы атака смогла пройти сквозь первый этап фильтрации, 
    IP и MAC адреса источника пакета должны соответствовать входному порту и идентификатору коммутатора, 
    на который этот пакет пришел, согласно таблице привязок.
