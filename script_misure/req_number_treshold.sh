cd /home/ric/nghttp2

reset

echo "Request number treshold"

H1_CLIENTS=6
MAX_STREAM_COEFF=2

MEASURE_COUNT=15


echo ""
echo "---------------"
echo "1KB"
echo "- - - - - - - -"
echo ""
for i in `seq 1 20`;
do
    echo "---------------"
    echo "$i richieste"
    echo ""
    echo "h1"
    for j in `seq 1 $MEASURE_COUNT`
    do
        h2load -n$i --h1 -c$((i>H1_CLIENTS ? H1_CLIENTS : i)) https://web-server-h2.duckdns.org:9000/1KB.txt | awk /^finished/ | awk '{split($0,a); print a[3];}' | tr -d ","
    done
    echo ""
    echo "h2"
    for j in `seq 1 $MEASURE_COUNT`
    do
        h2load -n$i -f16777215 -m$((i*MAX_STREAM_COEFF)) https://web-server-h2.duckdns.org:9000/1KB.txt| awk /^finished/ | awk '{split($0,a); print a[3];}' | tr -d ","
    done
done

echo ""
echo "---------------"
echo "10KB"
echo "- - - - - - - -"
echo ""
for i in `seq 1 25`;
do
    echo "---------------"
    echo "$i richieste"
    echo ""
    echo "h1"
    for j in `seq 1 $MEASURE_COUNT`
    do
        h2load -n$i --h1 -c$((i>H1_CLIENTS ? H1_CLIENTS : i)) https://web-server-h2.duckdns.org:9000/10KB.txt | awk /^finished/ | awk '{split($0,a); print a[3];}' | tr -d ","
    done
    echo ""
    echo "h2"
    for j in `seq 1 $MEASURE_COUNT`
    do
        h2load -n$i -f16777215 -m$((i*MAX_STREAM_COEFF)) https://web-server-h2.duckdns.org:9000/10KB.txt| awk /^finished/ | awk '{split($0,a); print a[3];}' | tr -d ","
    done
done

echo ""
echo "---------------"
echo "100KB"
echo "- - - - - - - -"
echo ""
for i in `seq 1 30`;
do
    echo "---------------"
    echo "$i richieste"
    echo ""
    echo "h1"
    for j in `seq 1 $MEASURE_COUNT`
    do
        h2load -n$i --h1 -c$((i>H1_CLIENTS ? H1_CLIENTS : i)) https://web-server-h2.duckdns.org:9000/img/100KB.jpg | awk /^finished/ | awk '{split($0,a); print a[3];}' | tr -d ","
    done
    echo ""
    echo "h2"
    for j in `seq 1 $MEASURE_COUNT`
    do
        h2load -n$i -f16777215 -m$((i*MAX_STREAM_COEFF)) https://web-server-h2.duckdns.org:9000/img/100KB.jpg| awk /^finished/ | awk '{split($0,a); print a[3];}' | tr -d ","
    done
done