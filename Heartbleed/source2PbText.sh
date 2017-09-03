srcml src.c -o src.xml
javac ProcessXML.java
#我是注释行
java ProcessXML
./ComXMLBiYacc get srcProcessed.xml srcAST
if [ ! -d "/srcPb.txt" ]; then
  sudo mkdir /srcPb.txt
fi
echo "" > srcPb.txt
./ComPBBiYacc put srcPb.txt srcAST
javac ProcessProto.java
#我是注释行
java ProcessProto
cat srcPbProcessed.txt | protoc --encode=fast.Data fast.proto>src.pb
cat src.pb | protoc --decode=fast.Data fast.proto>srcPbProcessed.txt
