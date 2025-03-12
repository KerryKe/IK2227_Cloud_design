$TTL    86400
@       IN      SOA     clustera.com. admin.clustera.com. (
                  1     ; Serial
             604800     ; Refresh
              86400     ; Retry
            2419200     ; Expire
              86400 )   ; Negative Cache TTL
;
@       IN      NS      clustera.com.
@       IN      A       10.0.200.1

