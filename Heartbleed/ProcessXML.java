import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * 
 * @author lichunmiao
 * 把srcml生成的xml文件转化为喂给biyacc的xml
 *
 */

public class ProcessXML {

    public static void main(String[] args) {
        File file = new File("/Users/lichunmiao/Desktop/ICSE18Paper/Heartbleed/src.xml");
        
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
        
        //现在所有的字符都存在了inputString中，下面对inputString进行预处理
        
        String outputString = "";
        int start = 0;
        int rightBracketPos = inputString.indexOf('>');
        int nextLeftBracketPos = inputString.indexOf('<', rightBracketPos);
        String tempString = "";
        String tempString2 = "";
        
        while(rightBracketPos < inputString.length() 
                && nextLeftBracketPos < inputString.length() 
                && rightBracketPos < nextLeftBracketPos)
        {
            tempString2 = "";
            
            if(inputString.substring(start,rightBracketPos+1).equals("<literal type=\"string\">"))
            {
                tempString2 += "\"\\"+ inputString.substring(rightBracketPos+1, nextLeftBracketPos-1) + "\\\"\"";   
            }
            else
            {
                tempString = inputString.substring(rightBracketPos+1, nextLeftBracketPos);
                //取出右尖括号和下一个左尖括号之间的内容，存放在tempString中,对其进行可能的加双引号操作或者不加双引号操作
                
                String temp1 = "";
                for(int i=0;i<tempString.length();i++)
                {
                    if(tempString.charAt(i) == '\"')
                        temp1 += "\\\"";
                    else if(tempString.charAt(i) == '\\')
                        temp1 += "\\\\";
                    else
                        temp1 += (tempString.charAt(i) + "");
                }
                
                tempString = temp1;
                
                int i=0;
                while(i<tempString.length())
                {
                    if(tempString.charAt(i) == '\n'
                            || tempString.charAt(i) == '\t'
                            || tempString.charAt(i) == ' ') 
                    {
                        tempString2 += tempString.substring(i, i+1);
                        i++;
                    }
                    else
                    {
                        tempString2 += "\"";
                    
                        int iniQuot = i;
                    
                        int endQuot = tempString.length()-1;
                        while(endQuot > iniQuot)
                        {
                            if(tempString.charAt(endQuot) != '\n'
                                   && tempString.charAt(endQuot) != '\t'
                                   && tempString.charAt(endQuot) != ' ') 
                                break;
                            else
                                endQuot--;
                        }
                    
                        tempString2 += tempString.substring(iniQuot, endQuot+1) + "\"";
                    
                        if(endQuot+1 < tempString.length())
                            tempString2 += tempString.substring(endQuot+1, tempString.length());
 
                        break;  
                    }
                }
            }
                
            outputString += inputString.substring(start, rightBracketPos+1) + tempString2;
            
            start = nextLeftBracketPos;
            
            rightBracketPos = inputString.indexOf('>', nextLeftBracketPos);
            nextLeftBracketPos = inputString.indexOf('<', rightBracketPos);
            
            if(nextLeftBracketPos == -1)
                 outputString += inputString.substring(start, inputString.length());
        }
  
        
        //此处的outputString已经在原有的xml文件上加上了相应的双引号，保证只要>和<之间有字符，就当作字符串进行后续处理
       
        //下面将outputString写入新的xml文件中

        File file2 = new File("/Users/lichunmiao/Desktop/ICSE18Paper/Heartbleed/srcProcessed.xml");
        
        if(!file2.exists())      
        {      
            try {      
                file2.createNewFile();      
            } catch (IOException e) {         
                e.printStackTrace();      
            }      
        } 
        
        try {  
            FileWriter fileWriter = new FileWriter(file2);  
            String s = new String(outputString);  
            fileWriter.write(s);  
            fileWriter.close(); // 关闭数据流  
  
        } catch (Exception e) {  
            e.printStackTrace();  
        } 
      }
}
