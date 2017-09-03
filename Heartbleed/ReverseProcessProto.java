import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.InputStreamReader;

/**
 * 
 * @author lichunmiao
 * 把从binary decode出来的proto text文件转化为喂给biyacc的proto text文件
 *
 */

public class ReverseProcessProto {
    public static void main(String[] args) {
        File file = new File("/Users/lichunmiao/Desktop/ICSE18Paper/Heartbleed/modifiedPbProcessed.txt");
        
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
        
        //现在所有的字符都存在了inputString中，下面对inputString进行处理,转化为biyacc接受的格式
        //注意：pb在从binary decode回textual形式的时候，把layout已经改变，所以先把layout变得跟之前从biyacc生成的pb textual形式转换的方便encode的形式
        
        //把pb decode形式转换
        String outputString = "";
 
        inputString = inputString.replace("element {", "");
       
        int i = 0;
        int tempIndex = 0;
        
        while( i < inputString.length())
        {
            if(i+4 < inputString.length() && inputString.substring(i, i+5).equals("tail:")) //需要把tail变成text并连同值提到比本级下面更高的一级
            {
                int j = i+7;
                
                while(j<inputString.length())
                {
                    if(inputString.charAt(j) == '\\')
                        j += 2;
                    else if (inputString.charAt(j) == '\"')
                        break;
                    else
                        j++;
                }
                
                tempIndex = inputString.indexOf('}', j+1);
                
                String temp = encoEsca(inputString.substring(i+7, tempIndex));
                
                outputString += ("}" + " text: \""+ temp);
                
                i = tempIndex + 1;
                continue;
                
            }
            /*else if(i+4 < inputString.length() && inputString.substring(i, i+5).equals("text:")) //对text对应的value值中的$\n$变为\n,$\t$变为\t
            {
                tempIndex = inputString.indexOf('\"', inputString.indexOf('\"',i+7));
                
                String temp = encoEsca(inputString.substring(i+7, inputString.indexOf('\"',i+7)));
                
                outputString += ("text: \""+ temp + "\"");
                
                i = tempIndex + 1;
                continue;   
            }*/
            else if(i+3 < inputString.length() && inputString.substring(i, i+4).equals("$\\n$"))
            {
                outputString += '\n';
                i += 4;
                continue;
            }
            else if(i+3 < inputString.length() && inputString.substring(i, i+4).equals("$\\t$"))
            {
                outputString += '\t';
                i += 4;
                continue;
            }
            else if (i+1 < inputString.length() && inputString.subSequence(i, i+2).equals("\\'"))
            {
                outputString += '\'';
                i += 2;
                continue;
            }
            else if(i+4 < inputString.length() && inputString.subSequence(i, i+5).equals("kind:"))
            {
                tempIndex = inputString.indexOf(" ", i+6);
                
                outputString += "kind: " + inputString.substring(i+5, tempIndex).toLowerCase(); //把kind值变为全小写
                
                i = tempIndex;
                continue;
                
            }
            else if(i+6 < inputString.length() && inputString.subSequence(i, i+7).equals("literal"))
            {
                //literal 里面只有type一个element
                
                tempIndex = inputString.indexOf("type: ",i+9);
                
                int tempIndex2 = inputString.indexOf("\n", tempIndex+6);
                
                String tempStr = inputString.substring(tempIndex+6, tempIndex2);
                
                switch(tempStr){
                  case "string_type": tempStr = "\"string\"";
                                      break;
                  case "number_type": tempStr = "\"number\"";
                                      break;
                  case "char_type": tempStr = "\"char\"";
                                      break;
                  case "boolean_type": tempStr = "\"boolean\"";
                                      break;
                  case "null_type": tempStr = "\"null\"";
                                      break;  
                }
                
                outputString += (inputString.substring(i, tempIndex+6) + tempStr);
                
                i = tempIndex2;
                continue;
            }
            else if(i+10 < inputString.length() && inputString.substring(i, i+11).equals("language: C"))
            {
                outputString += "language: \"C\"";
                
                i = i+11;
                continue;
                
            }
            
            if(i+1 <= inputString.length())
             outputString += inputString.substring(i, i+1);
            i++;
        }
        
        outputString = outputString.substring(0, outputString.length()-2);
     
        //下面将outputString写入新的xml文件中

        File file2 = new File("/Users/lichunmiao/Desktop/ICSE18Paper/Heartbleed/modifiedPb.txt");
        
        try {  
            FileWriter fileWriter = new FileWriter(file2);  
            String s = new String(outputString);  
            fileWriter.write(s);  
            fileWriter.close(); // 关闭数据流  
  
        } catch (Exception e) {  
            e.printStackTrace();  
        } 
      }
    
    private static String encoEsca(String inputString) {
        String outputString = "";
        
        for(int i=0;i<inputString.length();)
        {
            if(i+3 < inputString.length() && inputString.substring(i, i+4).equals("$\\n$"))
            {
                outputString += '\n';
                i += 4;
            }
            else if(i+3 < inputString.length() && inputString.substring(i, i+4).equals("$\\t$"))
            {
                outputString += '\t';
                i += 4;
            }
            else if (i+1 < inputString.length() && inputString.subSequence(i, i+2).equals("\\'"))
            {
                outputString += '\'';
                i += 2;
            }
            else 
            {
                outputString += inputString.charAt(i);
                i ++;
            }
        }
        
        return outputString;
        
    }
}
