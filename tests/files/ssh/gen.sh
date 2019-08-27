#! /bin/sh

rm *.key *.pub

ecbits="ecbits.txt"
echo 521 > "$ecbits"
getecbits() {
    last=$(cat $ecbits)
    case "$last" in
    256) last=384;;
    384) last=521;;
    521) last=256;;
    esac
    echo $last > "$ecbits"
    echo $last
}

genkey() {
    fn="$1"
    args="-f $fn -C $fn"
    case "$fn" in
    new-*) args="$args -o" ;;
    esac
    case "$fn" in
    *-ecdsa-*) args="$args -t ecdsa -b $(getecbits)" ;;
    *-rsa-*) args="$args -t rsa" ;;
    *-dsa-*) args="$args -t dsa" ;;
    *-ed25519-*) args="$args -t ed25519" ;;
    esac
    password=''
    case "$fn" in
    *-psw.*) password="password" ;;
    esac
    echo ssh-keygen -q $args -N "$password"
    ssh-keygen -q $args -N "$password"
}

for fmt in old new; do
    for ktype in rsa dsa ecdsa ed25519; do
        for psw in nopsw psw; do
            if test "$fmt-$ktype" = "old-ed25519"; then
                continue
            fi
            genkey "${fmt}-${ktype}-${psw}.key"
        done
    done
done

for fn in *.key; do
  ssh-keygen -q -y -f "$fn" > /dev/null
done

rm -f "$ecbits"
