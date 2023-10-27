package org.mycard.common;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Timer {
    final private static Logger log = LoggerFactory.getLogger(Timer.class);

    private long start = System.currentTimeMillis();

    public String getMsg(){
        StringBuffer stringBuffer = new StringBuffer();

        long now = System.currentTimeMillis();
        long dif = now - start;

        long secondsTotal = dif / 1000;
        long minutesTotal = secondsTotal / 60;
        long hoursTotal = minutesTotal / 60;


        long rest = dif;
        long hours = rest / 1000 / 60 / 60; rest = rest - (hours * 1000 * 60 * 60);
        long minutes = rest / 1000 / 60; rest = rest - (minutes * 1000 * 60);
        long seconds = rest / 1000; rest = rest - (seconds * 1000);



        if(hours!=0)  stringBuffer.append(String.format("%02d", hours)).append(":");
        if(minutes!=0)  stringBuffer.append(String.format("%02d", minutes)).append(":");
        stringBuffer.append(String.format("%02d", seconds)).append(".");
        stringBuffer.append(String.format("%03d", rest));

        return stringBuffer.toString();
    }

    public void reset() {
        this.start = System.currentTimeMillis();
    }

    public static void main(String[] args) throws InterruptedException {
        Timer timer = new Timer();
        Thread.sleep(5521);
        System.out.println(timer.getMsg());
    }
}
