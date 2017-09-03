import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.InputStreamReader;

/**
 * 
 * @author lichunmiao
 * 把biyacc生成的proto text文件转化为支持进行encode成binary的proto text文件
 *
 */

public class ProcessProto {

    public static void main(String[] args) {
        File file = new File("/Users/lichunmiao/Desktop/ICSE18Paper/Heartbleed/srcPb.txt");
        
        String inputString = "";
        InputStreamReader reader = null;
        try {
            //System.out.println("以字符为单位读取文件内容，一次读一个字节：");
            // 一次读一个字符,真的是“一个”字符“一个”字符啊。。。
            reader = new InputStreamReader(new FileInputStream(file));
            int tempchar;
            while ((tempchar = reader.read()) != -1) {
                if (((char) tempchar) != '\r') {
                    inputString += (char) tempchar;
                }
            }
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        //现在所有的字符都存在了inputString中，下面对inputString进行预处理, 将处理后的结果存在outputString中
        
        String outputString = "";
        
        outputString += "element {";
        
        int i = 0;
        
        int tempIndex = 0;
        
        if(inputString.charAt(0) == '\n')
            inputString = inputString.substring(1, inputString.length());
        
        while(i < inputString.length())
        {
            if(i+4 < inputString.length() && inputString.substring(i, i+5).equals("kind:"))
            {
                tempIndex = inputString.indexOf(" ", i+7);
                
                outputString += "kind: " + inputString.substring(i+6, tempIndex).toUpperCase(); //把kind值变为全大写
                
                i = tempIndex;
                continue;
                
            }
            else if(i+5 < inputString.length() && inputString.substring(i, i+6).equals("text: ")) //只是修改text之后的双引号里面的\n,\t
            {
                
                tempIndex = i+7;
                
                while(tempIndex < inputString.length())
                {
                    if(inputString.charAt(tempIndex) == '\\')
                        tempIndex += 2;
                    else if(inputString.charAt(tempIndex) == '\"')
                        break;
                    else
                        tempIndex ++;
                }
                        
                String temp = decoEsca(inputString.substring(i+7, tempIndex));  

                outputString += "text: \"" + temp;
                
                i = tempIndex;
                
                continue;
            }
            else if(inputString.charAt(i) == '}')
            {
                //把 } 后面的text变为tail,并加进上层的child中
                if(i+5 < inputString.length() && inputString.substring(i+2, i+6).equals("text"))
                {
                    
                    tempIndex = i+9;
                    
                    while(tempIndex < inputString.length())
                    {
                        if(inputString.charAt(tempIndex) == '"')
                        {
                            if(inputString.charAt(tempIndex - 1) != '\\')
                                break;
                            else
                                tempIndex ++;
                        }
                        else
                            tempIndex ++;
                    }
                            
                    String temp = decoEsca(inputString.substring(i+9, tempIndex));  

                    outputString += "tail: \"" + temp + "\" }";
                    
                    i = tempIndex + 1;
                    
                    continue;
                }
    
            }
            /*下面处理一些小minors,比如literal type的string变成string_type, language的值由"java"变成JAVA*/   
            else if(i+6 < inputString.length() && inputString.substring(i, i+7).equals("literal"))
            {
                //literal 里面只有type一个element
                
                tempIndex = inputString.indexOf("type: ",i+9);
                
                int tempIndex2 = inputString.indexOf("\"", tempIndex+7);
                
                String tempStr = inputString.substring(tempIndex+7, tempIndex2);
                
                switch(tempStr){
                  case "string": tempStr = "string_type";
                                      break;
                  case "number": tempStr = "number_type";
                                      break;
                  case "char": tempStr = "char_type";
                                      break;
                  case "boolean": tempStr = "boolean_type";
                                      break;
                  case "null": tempStr = "null_type";
                                      break;
                }
                
                outputString += (inputString.substring(i, tempIndex+6) + tempStr);
                
                i = tempIndex2+1;
                continue;
            }
            else if(i+12 < inputString.length() && inputString.substring(i, i+13).equals("language: \"C\""))
            {
                outputString += "language: C";
                
                i = i+13;
                continue;
                
            }
            
            
            outputString += inputString.charAt(i);
            
            i++;
        }
       
        
        outputString +=  "\n}";
       
        //下面将outputString写入新的文件中

        File file2 = new File("/Users/lichunmiao/Desktop/ICSE18Paper/Heartbleed/srcPbProcessed.txt");
        
        try {  
            FileWriter fileWriter = new FileWriter(file2);  
            String s = new String(outputString);  
            fileWriter.write(s);  
            fileWriter.close(); // 关闭数据流  
  
        } catch (Exception e) {  
            e.printStackTrace();  
        } 
      }

    private static String decoEsca(String inputString) {
        String outputString = "";
        
        for(int i=0;i<inputString.length();i++)
        {
            if(inputString.charAt(i) == '\n')
                outputString += "$\\n$";
            else if(inputString.charAt(i) == '\t')
                outputString += "$\\t$";
            else 
                outputString += inputString.charAt(i);
        }
        
        return outputString;
        
    }
    
      
}
