package com.ldifcheck.util;

import java.io.PrintWriter;

public class ProgressBar {

    private static final int TOTAL_LENGTH = 30;

    private final int max;
    private final PrintWriter writer;
    private int current;

    public ProgressBar(PrintWriter writer, int max) {
        this.writer = writer;
        this.max = max;
        outputCurrent("");
    }

    public void step(String suffix) {
        current++;
        if (current == max) {
            finish(suffix);
        } else {
            outputCurrent(suffix);
        }
    }

    private void outputCurrent(String suffix) {
        double currentPercentage = (double) current / max;
        int numCharacters = (int) Math.floor(currentPercentage * TOTAL_LENGTH);
        String currentProgress = repeatChar("=", numCharacters - 1) + ">";
        String remaining = repeatChar(" ", TOTAL_LENGTH - Math.max(numCharacters, 1));
        writer.printf("\r[%s%s] %s", currentProgress, remaining, suffix);
    }

    public void finish(String suffix) {
        String finalOutput = repeatChar("=", TOTAL_LENGTH - 1) + ">";
        writer.printf("\r[%s] %s\n", finalOutput, suffix);
    }

    private String repeatChar(String character, int numTimes) {
        if (numTimes <= 0) {
            return "";
        }
        return new String(new char[numTimes]).replace("\0", character);
    }
}
