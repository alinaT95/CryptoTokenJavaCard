package org.mycard.common;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.mycard.common.ByteArrayHelper.bytes;
import static org.mycard.common.ByteArrayHelper.hex;


public class TLV {
    final private static Logger log = LoggerFactory.getLogger(TLV.class);

    public byte[] tag;
    public byte[] value;
    public int totalLength;


    private static final StringBuilder tagBuilder = new StringBuilder();

    public static TLV parse(byte[] raw)
    {
        TLV result = new TLV();

        //Parse tag
        tagBuilder.setLength(0);
        int i = 0;
        if((raw[i]&0x1F)!=0x1F)
        {
            tagBuilder.append(String.format("%02X", raw[i++]));
        }
        else {
            tagBuilder.append(String.format("%02X", raw[i++]));

            do
            {
                byte next = raw[i++];
                tagBuilder.append(String.format("%02X", next & 0x7F));
                if((raw[i]&0x80)==0) break;
            } while(true);
        }
        result.tag = bytes(tagBuilder.toString());

        // Parse len
        int len = 0;
        int lenOfLen = 1;
        if((raw[i]&0x80)==0)
        {
            len = raw[i++];
        }
        else {
            lenOfLen = raw[i++] & 0x7F;
            for (int j = 0; j < lenOfLen; j++) {
                len |= (raw[i++] & 0xFF) << (8*(lenOfLen-j-1));
            }
            lenOfLen += 1;
        }

        // Parse value
        result.value = new byte[len];
        System.arraycopy(raw, result.tag.length + lenOfLen, result.value, 0, len);

        result.totalLength = result.tag.length + lenOfLen + result.value.length;

        return result;
    }

    public static byte[] serialize(Map<String, String> tlvMap) throws IOException {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        for (Map.Entry<String, String> entry : tlvMap.entrySet()) {
            TLV tlv = new TLV();
            tlv.tag = bytes(entry.getKey());
            tlv.value = bytes(entry.getValue());
            result.write(serialize(tlv));
        }
        return result.toByteArray();
    }

    public static byte[] serialize(TLV tlv) throws IOException {
        ByteArrayOutputStream result = new ByteArrayOutputStream();

        // Tag
        result.write(tlv.tag);

        // Len
        int length = tlv.value.length;
        if(length<=127)
        {
            result.write((byte)length);
        }
        else if(length>127 && length <= 255){
            result.write((byte)0x81); // 10000001
            result.write((byte)length);
        }
        else if (length>255 && length <= 65535){
            result.write((byte)0x82); // 10000010
            result.write((byte)(length >> 8));
            result.write((byte)length);
        }

        // Value
        result.write(tlv.value);

        return result.toByteArray();
    }

    public static Map<String, String> parseMap(byte[] raw)
    {
        HashMap<String, String> result = new HashMap<>();
        byte[] rest = raw;
        int i = 0;
        while(rest.length > 0)
        {
            TLV parse = parse(rest);
            result.put(hex(parse.tag), hex(parse.value));
            i += parse.totalLength;
            rest = new byte[raw.length - i];
            System.arraycopy(raw, i, rest, 0, raw.length - i);
        }

        return result;
    }

    @Override
    public String toString() {
        return hex(tag) + " - " + hex(value) + " (total len: "+totalLength+")";
    }

}
