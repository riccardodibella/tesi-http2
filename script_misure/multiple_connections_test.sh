reset

cd /home/ric/nghttp2

SESSIONS_PER_TEST=20
REQ_PER_SESSION=100

echo "-------------------"
echo "1 connection"
echo "- - - - - - - - - -"
for j in `seq 1 $SESSIONS_PER_TEST`
do
    h2load -f16777215 -n$REQ_PER_SESSION -c1 -m$((REQ_PER_SESSION*2)) https://web-server-h2.duckdns.org:9000/img/25KB.jpg | awk /^finished/ | awk '{split($0,a); print a[3];}' | tr -d ","
done
echo "-------------------"
echo "2 connections"
echo "- - - - - - - - - -"
for j in `seq 1 $SESSIONS_PER_TEST`
do
    h2load -f16777215 -n$REQ_PER_SESSION -c2 -m$((REQ_PER_SESSION*2)) https://web-server-h2.duckdns.org:9000/img/25KB.jpg | awk /^finished/ | awk '{split($0,a); print a[3];}' | tr -d ","
done
echo "-------------------"
echo "3 connections"
echo "- - - - - - - - - -"
for j in `seq 1 $SESSIONS_PER_TEST`
do
    h2load -f16777215 -n$REQ_PER_SESSION -c3 -m$((REQ_PER_SESSION*2)) https://web-server-h2.duckdns.org:9000/img/25KB.jpg | awk /^finished/ | awk '{split($0,a); print a[3];}' | tr -d ","
done
echo "-------------------"
echo "4 connections"
echo "- - - - - - - - - -"
for j in `seq 1 $SESSIONS_PER_TEST`
do
    h2load -f16777215 -n$REQ_PER_SESSION -c4 -m$((REQ_PER_SESSION*2)) https://web-server-h2.duckdns.org:9000/img/25KB.jpg | awk /^finished/ | awk '{split($0,a); print a[3];}' | tr -d ","
done
echo "-------------------"
echo "5 connections"
echo "- - - - - - - - - -"
for j in `seq 1 $SESSIONS_PER_TEST`
do
    h2load -f16777215 -n$REQ_PER_SESSION -c5 -m$((REQ_PER_SESSION*2)) https://web-server-h2.duckdns.org:9000/img/25KB.jpg | awk /^finished/ | awk '{split($0,a); print a[3];}' | tr -d ","
done
echo "-------------------"
echo "6 connections"
echo "- - - - - - - - - -"
for j in `seq 1 $SESSIONS_PER_TEST`
do
    h2load -f16777215 -n$REQ_PER_SESSION -c6 -m$((REQ_PER_SESSION*2)) https://web-server-h2.duckdns.org:9000/img/25KB.jpg | awk /^finished/ | awk '{split($0,a); print a[3];}' | tr -d ","
done
