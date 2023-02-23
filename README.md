# Lab6
## Лабораторная работа - ARP-spoofer
### 1. Поднять в одной сети две виртуальные машины: машину атакующего и машину жертвы. Требований по машинам, как рекомендация - сделать одну из машин (атакующего) kali.
#### Машина атакующего kali:
![2023-02-23_14-38-31](https://user-images.githubusercontent.com/122459067/220903959-66b20d22-f8e4-402e-87d4-81b785ba3190.png)
#### Машина жертвы:
![2023-02-23_16-27-02](https://user-images.githubusercontent.com/122459067/220926638-869a1f33-11d3-42a1-86ca-a3755a9d9cc2.png)
### 2. Исследовать ARP-таблицы и конфигурацию сети на обеих машинах, узнать адрес роутера.
![2023-02-23_17-11-42](https://user-images.githubusercontent.com/122459067/220933394-6257d7da-0598-400c-8d5e-75844f889cac.png)
![2023-02-23_17-16-54](https://user-images.githubusercontent.com/122459067/220933425-b0c8064a-5d80-4995-a9c7-b32768f374b2.png)

### 3. Необходимо подредактировать код arp_spoof.py (файл есть в материалах к занятию) таким образом, чтобы весь трафик машины-жертвы шел через машинку атакующего. На машине атакующего стоит проставить ip forwarding, чтобы на второй машине не пропало соединение с интернетом.
### 4. Запустить написанный скрипт на машине жертвы и исследовать arp-таблицу на машине-жертве.
### 5. Результатом выполнения домашнего задания должны стать три файла:
Доработанный файл с кодом arp_spoof.py.
Скриншот arp-таблицы на машине-жертве во время работы скрипта.
Вывод команд route -n, ifconfig eth0 на машине атакующего.
### 6. Advanced* (необязательное задание): написать функцию, восстанавливающую arp-таблицу на машине-жертвы после завершения атаки.
