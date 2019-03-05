BASEFILE=.testdata
APPFILE=./build/apps/encrypted_vim

#head -c 2m /dev/urandom | base64 > $BASEFILE
head -c 20 /dev/urandom | base64 > $BASEFILE
cp $BASEFILE ${BASEFILE}.bk
#encode
$APPFILE -e $BASEFILE
diff $BASEFILE ${BASEFILE}.bk
if [ $? -eq 0 ]; then
	echo "Failed to encode file"
	exit 1
fi
echo "Success to encode file"

$APPFILE -d $BASEFILE
diff $BASEFILE ${BASEFILE}.bk
if [ ! $? -eq 0 ]; then
	echo "Failed to decode file"
	exit 1
fi

echo "Success to decode file"
$APPFILE -e $BASEFILE
$APPFILE $BASEFILE
$APPFILE -d $BASEFILE
diff $BASEFILE ${BASEFILE}.bk
if [ ! $? -eq 0 ]; then
	echo "Failed to open encrypted file"
	exit 1
fi

rm $BASEFILE ${BASEFILE}.bk
echo "Finish test all, it's no problem!"
