package org.mycard.common;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ByteArrayHelper {
    final private static Logger log = LoggerFactory.getLogger(ByteArrayHelper.class);

    /**
     * Take count of bytes of array from the left side
     */
    public static byte[] bLeft(byte[] src, int count)
    {
        if(src == null) throw new IllegalArgumentException("Source array is null");
        if(count < 0) throw new IllegalArgumentException("Count is less than 0 ("+count+")");
        if(count > src.length) throw new IllegalArgumentException("Count is greater than length of source array ("+count+" > "+src.length+")");
        byte[] result = new byte[count];
        System.arraycopy(src, 0, result, 0, count);
        return result;
    }

    /**
     * Take count of bytes of array from the right side
     */
    public static byte[] bRight(byte[] src, int count) {
        if(src == null) throw new IllegalArgumentException("Source array is null");
        if(count < 0) throw new IllegalArgumentException("Count is less than 0 ("+count+")");
        if(count > src.length) throw new IllegalArgumentException("Count is greater than length of source array ("+count+" > "+src.length+")");
        byte[] result = new byte[count];
        System.arraycopy(src, src.length - count, result, 0, count);
        return result;
    }


    /**
     * Take a part from array
     */
    public static byte[] bSub(byte[] src, int from, int count) {
        if(src == null) throw new IllegalArgumentException("Source array is null");
        if(from < 0) throw new IllegalArgumentException("From is less than 0");
        if(from > src.length) throw new IllegalArgumentException("From is out of bound (" + from + ">" + (src.length) + ")");
        if(from + count > src.length) throw new IllegalArgumentException("End index is out of bound (" + (from + count) + ">" + (src.length) + ")");
        if(count < 0) throw new IllegalArgumentException("Count is less than 0 (" + count + ")");
        if(count > src.length -from) throw new IllegalArgumentException("Count is out of bound (count>src.length-from is "
                                                                         + count + ">" + (src.length - from) + ")");
        byte[] result = new byte[count];
        System.arraycopy(src, from, result, 0, count);
        return result;
    }

    public static byte[] bSub(byte[] src, int from) {
        return bSub(src, from, src.length - from);
    }

    /**
     * Arrays concatenation
     */

    // modified, null is taken into account
    public static byte[] bConcat(byte[]... arrays) {
        int totalLen = 0;
        for (byte[] array : arrays) {
            if (array != null)
                totalLen += array.length;
        }

        if (totalLen > 0) {
            int counter = 0;
            byte[] result = new byte[totalLen];
            for (byte[] array : arrays) {
                if (array != null) {
                    int len = array.length;
                    System.arraycopy(array, 0, result, counter, len);
                    counter += array.length;
                }
            }
            return result;
        }
        else return  null;
    }

    /**
     *  Array copy
     */
    public static byte[] bCopy(byte[] src) {
        if(src==null) throw new IllegalArgumentException("Source array is null");
        byte[] result = new byte[src.length];
        System.arraycopy(src,0,result,0,src.length);
        return result;
    }

    /**
     * Convert byte to hex-string
     */
    public static String hex(byte b) {
        return hex(new byte[]{b});
    }

    /**
     * Convert integer to hex-string representation
     */
    public static String hex(int i) {
        if(i <= 0xFF) return String.format("%02X", i);
        else if(i <= 0xFFFF) return String.format("%04X", i);
        else if(i <= 0xFFFFFF) return String.format("%06X", i);
        else return String.format("%08X", i);
    }

    /**
     * Convert byte array to hex-string
     */
    public static String hex(byte[] bytes) {
        if(bytes==null) throw new IllegalArgumentException("Source array is null");
        final char[] hexArray = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
        char[] hexChars = new char[bytes.length * 2];
        int v;
        for (int j = 0; j < bytes.length; j++) {
            v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * Convert hex-string to byte array
     */
    public static byte[] bytes(String s) {
        if(s==null) throw new IllegalArgumentException("Source string is null");
        if(s.length() % 2 != 0) throw new IllegalArgumentException("Source string is not correct hex: '"+s+"'");
        try {
            int len = s.length();
            byte[] data = new byte[len / 2];
            for (int i = 0; i < len; i += 2) {
                data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                        + Character.digit(s.charAt(i + 1), 16));
            }
            return data;
        } catch (Exception e) {
            throw new IllegalArgumentException("Source string is not correct hex: '"+s+"'");
        }
    }

    /**
     * Make byte array (1-byte length) from one byte
     */
    public static byte[] bytes(byte b) {
        return new byte[]{b};
    }

    /**
     * Make byte array from integer
     */
    public static byte[] bytes(int i) {
        if(i <= 0xFF) return new byte[]{(byte) i};
        else if(i <= 0xFFFF) return new byte[]{(byte) (i>>8),(byte) i};
        else if(i <= 0xFFFFFF) return new byte[]{(byte) (i>>16),(byte) (i>>8),(byte) i};
        else  return new byte[]{(byte) (i>>24),(byte) (i>>16),(byte) (i>>8),(byte) i};
    }

    public static String asciiToHex(String asciiStr) {
        char[] chars = asciiStr.toCharArray();
        StringBuilder hex = new StringBuilder();
        for (char ch : chars) {
            hex.append(Integer.toHexString((int) ch));
        }

        return hex.toString();
    }


    /**
     * Compare two byte arrays
     */
    public static boolean bEquals(byte[] first, byte[] second)
    {
        if(first==null) throw new IllegalArgumentException("First argument is null");
        if(second==null) throw new IllegalArgumentException("Second argument is null");
        if(first.length!=second.length) return false;
        for (int i = 0; i < first.length; i++) {
            byte b1 = first[i];
            byte b2 = second[i];
            if(b1!=b2) return false;
        }
        return true;
    }

}
