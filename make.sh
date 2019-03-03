PRIVATEFILE=.tmp.pem
if [ ! -e ${PRIVATEFILE} ]; then
#create encrypter_openssl_seed.cpp file to get private key on
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out ${PRIVATEFILE}
cat lib/src/encrypter_seed.cpp.in > lib/src/encrypter_seed.cpp
for line in `cat ${PRIVATEFILE} | grep -v "\-\-\-\-\-"`
do
	echo "${line}\\" >> lib/src/encrypter_seed.cpp
done
echo -n "\";
        return seed_data;
}
}
">> lib/src/encrypter_seed.cpp
fi

mkdir -p build
cd build
cmake ../
cmake --build .
