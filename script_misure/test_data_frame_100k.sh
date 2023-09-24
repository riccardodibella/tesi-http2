reset

cd /home/ric/nghttp2

SESSIONS_PER_TEST=100
REQ_PER_SESSION=100

for j in `seq 1 $SESSIONS_PER_TEST`
do
    h2load -f16777215 -n$REQ_PER_SESSION -c1 -m$((REQ_PER_SESSION*2)) https://web-server-h2.duckdns.org:9000/img/100KB.jpg | awk /^finished/ | awk '{split($0,a); print a[3];}' | tr -d ","
done
