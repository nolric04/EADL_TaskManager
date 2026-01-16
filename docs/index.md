# Resolution du .bash_aliases
## Comment le trouver
    type chmod

## /home/user/.bash_aliases

    - alias chmod=/pwet/chmod1.sh

## /pwet/chmod1.sh
    #!/usr/bin/env bash

    echo -e "\nCoucou !\n"
    /usr/bin/chmod "$@"
    echo -e "Au revoir !\n"

## Explication
    - Fais bien le chmod mais a integre des commandes supplementaires

---

---
# Resolution du /etc/passwd
    root:x:0:0:root:/root:/bin/bash
    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
    bin:x:2:2:bin:/bin:/usr/sbin/nologin
    sys:x:3:3:sys:/dev:/usr/sbin/nologin
    sync:x:4:65534:sync:/bin:/bin/sync
    games:x:5:60:games:/usr/games:/usr/sbin/nologin
    man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
    lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
    mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
    news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
    uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
    proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
    www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
    backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
    list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
    irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
    _apt:x:42:65534::/nonexistent:/usr/sbin/nologin
    nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
    systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
    dhcpcd:x:100:65534:DHCP Client Daemon:/usr/lib/dhcpcd:/bin/false
    systemd-timesync:x:991:991:systemd Time Synchronization:/:/usr/sbin/nologin
    messagebus:x:990:990:System Message Bus:/nonexistent:/usr/sbin/nologin
    sshd:x:989:65534:sshd user:/run/sshd:/usr/sbin/nologin
    user:x:1000:1000:user,,,:/home/user:/bin/bash
    my-app:x:1001:1001::/home/my-app:/bin/bash
    mysql:x:101:103:MariaDB Server:/nonexistent:/bin/false

## Explication
    le compte applicatif possède un compte utilisateur et possède un shell
        shell => vu avec /bin/bash

    Pourquoi c’est un problème en environnement maîtrise ?
    Cas normal d’un compte applicatif

    Un compte applicatif devrait :

    - executer un service
      - ne jamais se connecter en interactif
      - ne jamais ouvrir de session SSH
      - avoir un shell bloque (nologin / false)

    Or ici :
    - login possible
      - shell complet
      - execution de commandes arbitraires

---

---
# ss
    ss -lu
    State      Recv-Q     Send-Q                             Local Address:Port                    Peer Address:Port
    UNCONN     0          0                                  10.171.200.43:bootpc                       0.0.0.0:*
    UNCONN     0          0              [fe80::d89b:da02:f1fc:4c54]%ens33:dhcpv6-client                   [::]:*
## Erreur
0.0.0.0 => Autorise l'accès depuis tous les ports
## Correctif
    nano /etc/mysql/mariadb.conf.d/50-server.cnf
        #bind-address            = 127.0.0.1
        bind-address            = 0.0.0.0
        # Inverser puis systemctl
## Explication
    Un port UDP ouvert pour tout le monde peut être un vecteur d’attaque, même si le service est legitime.
    La bonne pratique : limiter l’exposition reseau, filtrer par firewall et surveiller le trafic.

---

---

# /etc/profile
## comment le trouver
    ls
    echo $PATH
    > /pwet:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
    type ls

## problème
    if [ "$(id -u)" -eq 0 ]; then
      PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    else
      PATH="/pwet:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games"
    fi

## Solution
    PATH securise pour root,
    mais un PATH volontairement detourne pour les utilisateurs,
    afin de faire passer des wrappers avant les commandes système.

# Accès aux mdp etc/shadow
## Problème
    ls -l /etc/shadow
    -rw-r--r-- 1 root shadow 896 Jan  8 15:21 /etc/shadow

## Solution
    chmod 640 /etc/shadow
    root@debian-secu:~# ls -l /etc/shadow
    -rw--w---- 1 root shadow 896 Jan  8 15:21 /etc/shadow
---

---
# Droits d'accès + git clone pour deploiement
## cat /etc/nginx/
## dans le /var/www/html
    ls -la /var/www/html/
    total 16
    drwxr-xr-x 3 root root 4096 Jan  8 15:43 .
    drwxr-xr-x 3 root root 4096 Jan  8 15:30 ..
    drwxrwxr-x 7 root root 4096 Jan  8 15:43 .git
    -rw-r--r-- 1 root root  615 Jan  8 15:30 index.nginx-debian.html

## Correctif
    Retirer le .git qui se retrouve accessible en curl
---

---
# /etc/ssh/sshd_config
## problème Accès ssh
## Correctif
Permit root login -> no
Autoriser des groupes à se connecter en ssh
Password_authentication -> no

---

---
# Accès mysql sans mot de passe
## problème
    mysql
    Accès autorise sans mdp.
## Risque
    => select * from mysql.user \G;
        Host: localhost
        User: root
        Password: invalid
---
        Host: localhost
        User: mysql
        Password: invalid
---
        Host: %
        User: app
        Password: *5BCB3E6AC345B435C7C2E6B7949A04CE6F6563D3
---
    MariaDB [(none)]>  show grants for 'app'@'%';
    +-------------------------------------------------------------------------------------------------------------+
    | Grants for app@%                                                                                            |
    +-------------------------------------------------------------------------------------------------------------+
    | GRANT ALL PRIVILEGES ON *.* TO `app`@`%` IDENTIFIED BY PASSWORD '*5BCB3E6AC345B435C7C2E6B7949A04CE6F6563D3' |
    +-------------------------------------------------------------------------------------------------------------+
## Explication
    - le user app peut se connecter depuis partout
    - root et mysql pas de MDP
    - le user a accès à toutes les bases
