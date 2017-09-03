#javac ReverseProcessProto.java
#我是注释行
#java ReverseProcessProto
./ComPBBiYacc get modifiedPb.txt srcAST
./ComXMLBiYacc put srcProcessed.xml srcAST
javac ReverseProcessXML.java
#我是注释行
java ReverseProcessXML
srcml src.xml -o src.c