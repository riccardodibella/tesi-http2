cd /home/ric/nghttp2

reset

NUM_REQ=100
NUM_TEST=100

echo "$NUM_REQ richieste - 25KB"
echo "-------------------"
echo "1 client - HTTP/1.1"
echo "- - - - - - - - - -"
for j in `seq 1 $NUM_TEST`
do
h2load --h1 -n$NUM_REQ -c1 https://web-server-h2.duckdns.org:9000/img/25KB.jpg  | awk /^finished/ | awk '{split($0,a); print a[3];}' | tr -d ","
done
echo "-------------------"
echo "1 stream - HTTP/2"
echo "- - - - - - - - - -"
for j in `seq 1 $NUM_TEST`
do
h2load -n$NUM_REQ -c1 -m1 https://web-server-h2.duckdns.org:9000/img/25KB.jpg  | awk /^finished/ | awk '{split($0,a); print a[3];}' | tr -d ","
done
echo "-------------------"
echo "6 client - HTTP/1.1"
echo "- - - - - - - - - -"
for j in `seq 1 $NUM_TEST`
do
h2load --h1 -n$NUM_REQ -c6 https://web-server-h2.duckdns.org:9000/img/25KB.jpg  | awk /^finished/ | awk '{split($0,a); print a[3];}' | tr -d ","
done
echo "-------------------"
echo "6 stream - HTTP/2"
echo "- - - - - - - - - -"
for j in `seq 1 $NUM_TEST`
do
h2load -n$NUM_REQ -c1 -m6 https://web-server-h2.duckdns.org:9000/img/25KB.jpg  | awk /^finished/ | awk '{split($0,a); print a[3];}' | tr -d ","
done
echo "-------------------"
echo "Max stream - HTTP/2"
echo "- - - - - - - - - -"
for j in `seq 1 $NUM_TEST`
do
h2load -n$NUM_REQ -c1 -m$((NUM_REQ*2)) https://web-server-h2.duckdns.org:9000/img/25KB.jpg  | awk /^finished/ | awk '{split($0,a); print a[3];}' | tr -d ","
done
