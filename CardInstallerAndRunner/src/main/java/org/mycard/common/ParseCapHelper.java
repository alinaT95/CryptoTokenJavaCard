package org.mycard.common;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class ParseCapHelper {
    final private static Logger log = LoggerFactory.getLogger(ParseCapHelper.class);

    private static final String[] order = {
            "Header.cap", "Directory.cap", "Import.cap", "Applet.cap", "Class.cap", "Method.cap", "StaticField.cap", "Export.cap", "ExportDescription.cap", "ConstantPool.cap",
            "RefLocation.cap", "Descriptor.cap"
    };

    public static byte[] read(File file) throws IOException {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        JarFile jarFile = new JarFile(file);
        Map<String, JarEntry> entryMap = toMap(jarFile.entries());
        for (String next : order) {
            JarEntry entry = entryMap.get(next);
            if(entry!=null)
            {
                log.debug(next);
                byte[] bytes = IOUtils.toByteArray(jarFile.getInputStream(entry));
                result.write(bytes);
            }
        }

        return result.toByteArray();
    }

    private static Map<String, JarEntry> toMap(Enumeration<JarEntry> entries)
    {
        HashMap<String, JarEntry> result = new HashMap<>();
        while(entries.hasMoreElements())
        {
            JarEntry entry = entries.nextElement();
            String name = entry.toString();
            if(!name.startsWith("META-INF"))
            {
                name = name.indexOf('/')>=0 ? name.substring(name.lastIndexOf('/') + 1) : name;
                result.put(name, entry);
            }
        }
        return  result;
    }


}
