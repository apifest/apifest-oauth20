/*
* Copyright 2013-2014, ApiFest project
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

package com.apifest.oauth20;

import java.util.Random;

/**
 * Utility class that generates random strings.
 *
 * @author Rossitsa Borissova
 */
public final class RandomGenerator {
    private static char[] charsSymbols = new char[56];
    private static char[] charsDigits = new char[16];
    private static char[] digits = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };

    static {
        for (int idx = 0; idx < 26; ++idx) {
            charsSymbols[idx] = (char) ('a' + idx);
        }
        for (int idx = 0; idx < 26; ++idx) {
            charsSymbols[idx + 26] = (char) ('A' + idx);
        }
        charsSymbols[52] = ('_');
        charsSymbols[53] = ('-');
        charsSymbols[54] = ('#');
        charsSymbols[55] = ('=');

        for (int idx = 0; idx < 6; ++idx) {
            charsDigits[idx] = (char) ('a' + idx);
        }
        for (int idx = 6; idx < 16; ++idx) {
            charsDigits[idx] = (char) ('0' + idx - 6);
        }
    }

    /**
     * Generates random string that contains chars (a-z, A-Z) and some symbols(_,-,#,=).
     * @param lenght the length of the generated string
     * @return random string
     */
    public static String generateCharsSymbolsString(int lenght) {
        StringBuffer buf = new StringBuffer(lenght);
        Random rand = new Random();
        for (int i = 0; i < lenght; i++) {
            buf.append(charsSymbols[rand.nextInt(charsSymbols.length)]);
        }
        return buf.toString();
    }

    /**
     * Generates random string that contains chars (a,b,c,d,e,f) and digits.
     * @param length the length of the generated string
     * @return random string
     */
    public static String generateCharsDigitsString(int length) {
        StringBuffer buf = new StringBuffer(length);
        Random rand = new Random();
        for (int i = 0; i < length; i++) {
            buf.append(charsDigits[rand.nextInt(charsDigits.length)]);
        }
        return buf.toString();
    }

    /**
     * Generates random string that contains digits only.
     * @param length the length of the generated string
     * @return random string
     */
    public static String generateDigitsString(int length) {
        StringBuffer buf = new StringBuffer(length);
        Random rand = new Random();
        for (int i = 0; i < length; i++) {
            buf.append(rand.nextInt(digits.length));
        }
        return buf.toString();
    }

}
