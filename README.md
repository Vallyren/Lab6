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
![2023-02-23_17-21-42](https://user-images.githubusercontent.com/122459067/220935524-c7d85635-35c3-4f7d-a4b8-d7070e346a2a.png)
![2023-02-23_17-26-26](https://user-images.githubusercontent.com/122459067/220935550-77e30121-7760-4d0f-a8a5-60fd2276cfa1.png)
### 3. Необходимо подредактировать код arp_spoof.py (файл есть в материалах к занятию) таким образом, чтобы весь трафик машины-жертвы шел через машинку атакующего. На машине атакующего стоит проставить ip forwarding, чтобы на второй машине не пропало соединение с интернетом.
![2023-02-24_14-25-49](https://user-images.githubusercontent.com/122459067/221173297-5b8ffbc2-257f-4577-ab48-815a6c817a6d.png)

![2023-02-24_14-53-34](https://user-images.githubusercontent.com/122459067/221173079-d43ac5ef-a319-4c2b-956a-065c867e81ce.png)

![2023-02-24_14-33-48](https://user-images.githubusercontent.com/122459067/221172136-39090dd4-ba5b-46a7-8e0e-fa9af32b83b9.png)
![2023-02-24_14-34-59](https://user-images.githubusercontent.com/122459067/221173335-8da4e5a1-706b-47b7-b344-97c655ef1cfe.png)
### 4. Запустить написанный скрипт на машине жертвы и исследовать arp-таблицу на машине-жертве.
![2023-02-24_14-23-25](https://user-images.githubusercontent.com/122459067/221172194-931bd109-ac06-42ba-9afe-1232d05f9f11.png)

### 5. Результатом выполнения домашнего задания должны стать три файла:
Доработанный файл с кодом arp_spoof.py.

Скриншот arp-таблицы на машине-жертве во время работы скрипта.
![2023-02-24_14-24-09](https://user-images.githubusercontent.com/122459067/221172342-e3720356-f480-4130-bc1e-2a16652f311a.png)

Вывод команд route -n, ifconfig eth0 на машине атакующего.
![2023-02-24_14-38-23](https://user-images.githubusercontent.com/122459067/221172395-67e1743a-7fdf-4d64-9f7f-2d8e1216876a.png)
![2023-02-24_14-39-10](https://user-images.githubusercontent.com/122459067/221172432-1e0e4e63-4752-4811-a038-52960b3d9c8d.png)

### 6. Advanced* (необязательное задание): написать функцию, восстанавливающую arp-таблицу на машине-жертвы после завершения атаки.
