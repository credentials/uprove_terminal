package service;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Properties;

/**
 * @author Pim Vullers
 * @version $Revision: 324 $ by $Author: pim $
 *          $LastChangedDate: 2010-11-19 16:40:03 +0100 (Fri, 19 Nov 2010) $
 */
public class TestVectorConverter {

    private static Properties testVectors = null; 
    
    /**
     * @param args
     */
    public static void main(String[] args) {
        testVectors = new Properties();
        try {
            testVectors.load(new FileInputStream("testvectors.txt"));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        String[] list = new String[testVectors.size()];
        
        Enumeration<?> e = testVectors.propertyNames();

        int i = 0;
        while (e.hasMoreElements()) {
          String key = (String) e.nextElement();
          list[i++] = "public static final byte[] " + key.toUpperCase() + " = {" + Hex.bytesToJavaHexString(Hex.hexStringToBytes(testVectors.getProperty(key))) + "};";          
        }

        Arrays.sort(list);
        for (int j = 0; j < list.length; j++) {
            System.out.println(list[j]);
        }
    }

}
