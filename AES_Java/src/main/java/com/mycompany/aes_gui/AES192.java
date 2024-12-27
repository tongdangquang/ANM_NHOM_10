/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.mycompany.aes_gui;

/**
 *
 * @author pvlon
 */
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

public class AES192 {
    private static final String[][] S_BOX = {
            {"63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76"},
            {"CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0"},
            {"B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15"},
            {"04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75"},
            {"09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84"},
            {"53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF"},
            {"D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8"},
            {"51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2"},
            {"CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73"},
            {"60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB"},
            {"E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79"},
            {"E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08"},
            {"BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A"},
            {"70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E"},
            {"E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF"},
            {"8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16"}
    };

    public static final String[][] INV_S_BOX = {
            {"52", "09", "6A", "D5", "30", "36", "A5", "38", "BF", "40", "A3", "9E", "81", "F3", "D7", "FB"},
            {"7C", "E3", "39", "82", "9B", "2F", "FF", "87", "34", "8E", "43", "44", "C4", "DE", "E9", "CB"},
            {"54", "7B", "94", "32", "A6", "C2", "23", "3D", "EE", "4C", "95", "0B", "42", "FA", "C3", "4E"},
            {"08", "2E", "A1", "66", "28", "D9", "24", "B2", "76", "5B", "A2", "49", "6D", "8B", "D1", "25"},
            {"72", "F8", "F6", "64", "86", "68", "98", "16", "D4", "A4", "5C", "CC", "5D", "65", "B6", "92"},
            {"6C", "70", "48", "50", "FD", "ED", "B9", "DA", "5E", "15", "46", "57", "A7", "8D", "9D", "84"},
            {"90", "D8", "AB", "00", "8C", "BC", "D3", "0A", "F7", "E4", "58", "05", "B8", "B3", "45", "06"},
            {"D0", "2C", "1E", "8F", "CA", "3F", "0F", "02", "C1", "AF", "BD", "03", "01", "13", "8A", "6B"},
            {"3A", "91", "11", "41", "4F", "67", "DC", "EA", "97", "F2", "CF", "CE", "F0", "B4", "E6", "73"},
            {"96", "AC", "74", "22", "E7", "AD", "35", "85", "E2", "F9", "37", "E8", "1C", "75", "DF", "6E"},
            {"47", "F1", "1A", "71", "1D", "29", "C5", "89", "6F", "B7", "62", "0E", "AA", "18", "BE", "1B"},
            {"FC", "56", "3E", "4B", "C6", "D2", "79", "20", "9A", "DB", "C0", "FE", "78", "CD", "5A", "F4"},
            {"1F", "DD", "A8", "33", "88", "07", "C7", "31", "B1", "12", "10", "59", "27", "80", "EC", "5F"},
            {"60", "51", "7F", "A9", "19", "B5", "4A", "0D", "2D", "E5", "7A", "9F", "93", "C9", "9C", "EF"},
            {"A0", "E0", "3B", "4D", "AE", "2A", "F5", "B0", "C8", "EB", "BB", "3C", "83", "53", "99", "61"},
            {"17", "2B", "04", "7E", "BA", "77", "D6", "26", "E1", "69", "14", "63", "55", "21", "0C", "7D"}
    };


    private static final String[][] RCON = {
            {"01", "02", "04", "08", "10", "20", "40", "80", "1B", "36"},
            {"00", "00", "00", "00", "00", "00", "00", "00", "00", "00"},
            {"00", "00", "00", "00", "00", "00", "00", "00", "00", "00"},
            {"00", "00", "00", "00", "00", "00", "00", "00", "00", "00"}
    };

    public static byte[] addPadding(byte[] input) {
        int paddingLength = 16 - (input.length % 16);
        byte[] paddedInput = new byte[input.length + paddingLength];
        System.arraycopy(input, 0, paddedInput, 0, input.length);
        for (int i = input.length; i < paddedInput.length; i++) {
            paddedInput[i] = (byte) paddingLength;
        }
        return paddedInput;
    }

    public static byte[] removePadding(byte[] input) {
        int paddingLength = input[input.length - 1];
        if (paddingLength < 1 || paddingLength > 16) {
            throw new IllegalArgumentException("Invalid padding length.");
        }
        byte[] output = new byte[input.length - paddingLength];
        System.arraycopy(input, 0, output, 0, output.length);
        return output;
    }

    public static String[][] convertToMaxtrix4x4(byte[] input) {
        int index = 0;
        String[][] state = new String[4][4];
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                state[row][col] = String.format("%02X", input[index]);
                index++;
            }
        }
        return state;
    }

    public static String[][] convertToMaxtrix4x6(byte[] input) {
        int index = 0;
        String[][] state = new String[4][6];
        for (int col = 0; col < 6; col++) {
            for (int row = 0; row < 4; row++) {
                state[row][col] = String.format("%02X", input[index]);
                index++;
            }
        }
        return state;
    }

    public static String matric4x4ToString(String[][] matrix) {
        String hex = "";
        for(int col = 0; col < 4; col++) {
            for(int row = 0; row < 4; row++) {
                hex += matrix[row][col];
            }
        }
        return hex;
    }

    public static void displayMatrix2D(String[][] input) {
        Arrays.stream(input).map(Arrays::toString).forEach(System.out::println);
    }

    public static void displayMatrix1D(String[] input) {
        System.out.println(Arrays.toString(input));
    }

    public static String[][] addRoundKey(String[][] state, String[][] key) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                int stateValue = Integer.parseInt(state[j][i], 16);
                int keyValue = Integer.parseInt(key[j][i], 16);
                int xorResult = stateValue ^ keyValue;
                state[j][i] = String.format("%02X", xorResult);
            }
        }
        return state;
    }

    public static String[][] subBytes(String[][] state) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                String hex = state[i][j];
                int row = Integer.parseInt(String.valueOf(hex.charAt(0)), 16);
                int col = Integer.parseInt(String.valueOf(hex.charAt(1)), 16);
                state[i][j] = S_BOX[row][col];
            }
        }
        return state;
    }

    public static String[][] invSubBytes(String[][] state) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                String hex = state[i][j];
                int row = Integer.parseInt(String.valueOf(hex.charAt(0)), 16);
                int col = Integer.parseInt(String.valueOf(hex.charAt(1)), 16);
                state[i][j] = INV_S_BOX[row][col];
            }
        }
        return state;
    }

    public static String[][] shiftRows(String[][] state) {
        for (int i = 1; i < 4; i++) {
            String[] row = state[i];
            String[] shiftedRow = new String[4];
            System.arraycopy(row, i, shiftedRow, 0, 4 - i);
            System.arraycopy(row, 0, shiftedRow, 4 - i, i);
            state[i] = shiftedRow;
        }
        return state;
    }

    public static String[][] invShiftRows(String[][] state) {
        for (int i = 1; i < 4; i++) {
            String[] row = state[i];
            String[] shiftedRow = new String[4];
            System.arraycopy(row, 4 - i, shiftedRow, 0, i);
            System.arraycopy(row, 0, shiftedRow, i, 4 - i);
            state[i] = shiftedRow;
        }
        return state;
    }


    public static String mixCol2(String hex) {
        int num = Integer.parseInt(hex.trim(), 16);
        // Kiểm tra bit đầu tiên (bit 7)
        if ((num & 0x80) == 0) {
            // Bit đầu = 0 -> Dịch trái 1 bit
            num = (num << 1) & 0xFF;
        } else {
            // Bit đầu = 1 -> Dịch trái 1 bit và XOR với 00011011 (0x1B)
            num = ((num << 1) ^ 0x1B) & 0xFF;
        }
        return String.format("%02X", num);
    }

    public static String mixCol3(String hex) {
        int num = Integer.parseInt(hex.trim(), 16);
        int temp = Integer.parseInt(mixCol2(hex), 16);
        num = (num ^ temp);
        return String.format("%02X", num);
    }

    public static String mixCol9(String hex) {
        int num = Integer.parseInt(hex, 16);
        int result = Integer.parseInt(mixCol2(mixCol2(mixCol2(hex))), 16) ^ num;
        return String.format("%02X", result);
    }

    public static String mixCol11(String hex) {
        int num = Integer.parseInt(hex, 16);
        int result = Integer.parseInt(mixCol2(mixCol2(mixCol2(hex))), 16) ^ Integer.parseInt(mixCol2(hex), 16) ^ num;
        return String.format("%02X", result);
    }

    public static String mixCol13(String hex) {
        int num = Integer.parseInt(hex, 16);
        int result = Integer.parseInt(mixCol2(mixCol2(mixCol2(hex))), 16) ^ Integer.parseInt(mixCol2(mixCol2(hex)), 16) ^ num;
        return String.format("%02X", result);
    }

    public static String mixCol14(String hex) {
        int result = Integer.parseInt(mixCol2(mixCol2(mixCol2(hex))), 16) ^ Integer.parseInt(mixCol2(mixCol2(hex)), 16) ^ Integer.parseInt(mixCol2(hex), 16);
        return String.format("%02X", result);
    }

    public static String[][] mixColumns(String[][] state) {
        int[][] mixColMatrix = {
                {2, 3, 1, 1},
                {1, 2, 3, 1},
                {1, 1, 2, 3},
                {3, 1, 1, 2}
        };
        String[][] result = new String[4][4];
        for (int col = 0; col < 4; col++) {
            int[] tempColumn = new int[4];
            for (int row = 0; row < 4; row++) {
                int tempValue = 0;
                for (int k = 0; k < 4; k++) {
                    int value = Integer.parseInt(state[k][col], 16);
                    if (mixColMatrix[row][k] == 1) {
                        tempValue ^= value;
                    } else if (mixColMatrix[row][k] == 2) {
                        tempValue ^= Integer.parseInt(mixCol2(state[k][col]), 16);
                    } else if (mixColMatrix[row][k] == 3) {
                        tempValue ^= Integer.parseInt(mixCol3(state[k][col]), 16);
                    }
                }
                tempColumn[row] = tempValue;
            }
            for (int row = 0; row < 4; row++) {
                result[row][col] = String.format("%02X", tempColumn[row]);
            }
        }
        return result;
    }

    public static String[][] invMixColumns(String[][] state) {
        int[][] invMixColMatrix = {
                {14, 11, 13, 9},
                {9, 14, 11, 13},
                {13, 9, 14, 11},
                {11, 13, 9, 14}
        };
        String[][] result = new String[4][4];
        for (int col = 0; col < 4; col++) {
            int[] tempColumn = new int[4];
            for (int row = 0; row < 4; row++) {
                int tempValue = 0;
                for (int k = 0; k < 4; k++) {
                    int value = Integer.parseInt(state[k][col], 16);
                    if (invMixColMatrix[row][k] == 9) {
                        tempValue ^= Integer.parseInt(mixCol9(state[k][col]), 16);
                    } else if (invMixColMatrix[row][k] == 11) {
                        tempValue ^= Integer.parseInt(mixCol11(state[k][col]), 16);
                    } else if (invMixColMatrix[row][k] == 13) {
                        tempValue ^= Integer.parseInt(mixCol13(state[k][col]), 16);
                    } else if (invMixColMatrix[row][k] == 14) {
                        tempValue ^= Integer.parseInt(mixCol14(state[k][col]), 16);
                    }
                }
                tempColumn[row] = tempValue;
            }
            for (int row = 0; row < 4; row++) {
                result[row][col] = String.format("%02X", tempColumn[row]);
            }
        }
        return result;
    }

    public static String xorBin(String binary1, String binary2) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < binary1.length(); i++) {
            result.append(binary1.charAt(i) == binary2.charAt(i) ? "0" : "1");
        }
        return result.toString();
    }

    private static String[] xorHex(String[] hex1, String[] hex2) {
        String[] result = new String[hex1.length];
        for (int i = 0; i < hex1.length; i++) {
            int n = Integer.parseInt(hex1[i], 16) ^ Integer.parseInt(hex2[i], 16);
            result[i] = String.format("%02X", n);
        }
        return result;
    }

    public static String[][] keyExpansion(String[][] initialisationKey) {
        String[][] key = initialisationKey;
        System.out.println("Original Key:");
        displayMatrix2D(key);

        String[][] expandKey = new String[4][52];
        String[] temp = new String[4];
        String[] word = new String[4];
        String[] w = new String[4];

        // Sao chép khóa gốc vào 6 cột đầu của expandKey
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 6; j++) {
                expandKey[i][j] = key[i][j];
            }
        }

        for (int col = 6; col < 52; col++) {
            if ((col % 6) == 0) {
                int rCol = (col / 6);
                // Lấy giá trị từ khóa hiện tại và RCON (dịch trái 1 byte)
                for (int j = 0; j < 4; j++) {
                    temp[j] = expandKey[j][col - 1];
                    word[j] = RCON[j][rCol - 1];
                    w[j] = expandKey[j][col - 6];
                }
                temp = rotWord(temp); // Xoay từ
                temp = subWord(temp); // Thay thế với S_BOX
                temp = xorHex(temp, word); // XOR với RCON
                temp = xorHex(temp, w); // XOR với từ trước đó
                for (int j = 0; j < 4; j++) {
                    expandKey[j][col] = temp[j];
                }
            }
            else {
                for (int j = 0; j < 4; j++) {
                    w[j] = expandKey[j][col - 6];
                    temp[j] = expandKey[j][col - 1];
                }
                temp = xorHex(temp, w); // XOR với từ trước đó
                for (int j = 0; j < 4; j++) {
                    expandKey[j][col] = temp[j];
                }
            }
        }
        System.out.println("Expansion Key:");
        displayMatrix2D(expandKey);
        return expandKey;
    }

    public static String[] rotWord(String[] word) {
        // 1234 thành 2341
        String temp = word[0];
        for (int i = 1; i < 4; i++) {
            word[i - 1] = word[i];
        }
        word[3] = temp;
        return word;
    }


    public static String[] subWord(String[] word) {
        String hex;
        int x, y;
        for (int i = 0; i < 4; i++) {
            hex = word[i];
            String j = "" + hex.charAt(0);
            String k = "" + hex.charAt(1);
            x = Integer.parseInt(j, 16);
            y = Integer.parseInt(k, 16);
            word[i] = S_BOX[x][y];
        }
        return word;
    }

    public static String hexToStringUTF8(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
        }
        return new String(data, StandardCharsets.UTF_8);
    }

    public static String[][] arrangeToMatrix4x4(String hex) {
        int index = 0;
        String[][] state = new String[4][4];
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                state[row][col] = hex.substring(index, index + 2);
                index += 2;
            }
        }
        return state;
    }

    public static byte[] hexToByteArray(String hex) {
        byte[] output = new byte[hex.length() / 2];
        for(int i = 0; i < hex.length(); i += 2) {
            String tmp = hex.substring(i, i + 2);
            output[i / 2] = (byte) Integer.parseInt(tmp, 16);
        }
        return output;
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    public static String encrypt_hex(String plaintext, String inputKey) {
        System.out.println("=============== ENCRYPT ===============");
        System.out.println("Key: " + inputKey);
        String[][] originalKey = convertToMaxtrix4x6(inputKey.getBytes());
        String[][] key = keyExpansion(originalKey);
        System.out.println("Plaintext: " + plaintext);
        for (byte b : plaintext.getBytes()) {
            System.out.print(b + "\t");
        }
        System.out.println();
        for (byte b : plaintext.getBytes()) {
            System.out.print(String.format("%02X", b) + "\t");
        }
        System.out.println();

        byte[] inputEncrypt = plaintext.getBytes();
        inputEncrypt = addPadding(inputEncrypt);
        System.out.println("Input length: " + inputEncrypt.length);

        String ciphertext = "";
        for(int v = 0; v < inputEncrypt.length; v += 16) {
            System.out.println("********** Sub Block **********");
            byte[] subInputEncrypt = new byte[16];
            int index = 0;
            for(int h = v; h < v + 16; h++) {
                subInputEncrypt[index] = inputEncrypt[h];
                index++;
            }
            System.out.println("Original state:");
            String[][] state = convertToMaxtrix4x4(subInputEncrypt);
            displayMatrix2D(state);

            System.out.println("---------- Round 0 ----------");
            System.out.println("Used Key:");
            String[][] keyRound0 = new String[4][4];
            for(int row = 0; row < 4; row++) {
                for(int col = 0; col < 4; col++) {
                    keyRound0[row][col] = key[row][col];
                }
            }
            displayMatrix2D(keyRound0);
            state = addRoundKey(state, key);
            System.out.println("State after AddRoundKey:");
            displayMatrix2D(state);

            for (int i = 0; i < 12 - 1; i++) {
                System.out.println("---------- Round " + (i + 1) + " ----------");
                state = subBytes(state);
                System.out.println("State after SubBytes:");
                displayMatrix2D(state);
                state = shiftRows(state);
                System.out.println("State after ShiftRows:");
                displayMatrix2D(state);
                state = mixColumns(state);
                System.out.println("State after MixColumns:");
                displayMatrix2D(state);
                System.out.println("Used Key:");
                String[][] keyUsed = new String[4][4];
                for(int row = 0; row < 4; row++) {
                    for(int col = (i + 1) * 4; col < (i + 1) * 4 + 4; col++) {
                        keyUsed[row][col % 4] = key[row][col];
                    }
                }
                displayMatrix2D(keyUsed);
                state = addRoundKey(state, keyUsed);
                System.out.println("State after AddRoundKey:");
                displayMatrix2D(state);
            }

            System.out.println("---------- Round 12 ----------");
            state = subBytes(state);
            System.out.println("State after SubBytes:");
            displayMatrix2D(state);
            state = shiftRows(state);
            System.out.println("State after ShiftRows:");
            displayMatrix2D(state);
            System.out.println("Used Key:");
            String[][] keyRound12 = new String[4][4];
            for(int row = 0; row < 4; row++) {
                for(int col = 48; col < 52; col++) {
                    keyRound12[row][col % 4] = key[row][col];
                }
            }
            displayMatrix2D(keyRound12);
            state = addRoundKey(state, keyRound12);
            System.out.println("State after AddRoundKey:");
            displayMatrix2D(state);

            String enCryptedText = "";
            System.out.println("Final State: ");
            displayMatrix2D(state);
            for(int col = 0; col < 4; col++) {
                for(int row = 0; row < 4; row++) {
                    enCryptedText += state[row][col];
                }
            }

            ciphertext += enCryptedText;
        }

        System.out.println("Ciphertext (HEX): " + ciphertext);

        return ciphertext;
    }

    public static String encrypt_base64(String plaintext, String inputKey) {
        System.out.println("=============== ENCRYPT ===============");
        System.out.println("Key: " + inputKey);
        String[][] originalKey = convertToMaxtrix4x6(inputKey.getBytes());
        String[][] key = keyExpansion(originalKey);
        System.out.println("Plaintext: " + plaintext);
        for (byte b : plaintext.getBytes()) {
            System.out.print(b + "\t");
        }
        System.out.println();
        for (byte b : plaintext.getBytes()) {
            System.out.print(String.format("%02X", b) + "\t");
        }
        System.out.println();

        byte[] inputEncrypt = plaintext.getBytes();
        inputEncrypt = addPadding(inputEncrypt);
        System.out.println("Input length: " + inputEncrypt.length);

        String ciphertext = "";
        for(int v = 0; v < inputEncrypt.length; v += 16) {
            System.out.println("********** Sub Block **********");
            byte[] subInputEncrypt = new byte[16];
            int index = 0;
            for(int h = v; h < v + 16; h++) {
                subInputEncrypt[index] = inputEncrypt[h];
                index++;
            }
            System.out.println("Original state:");
            String[][] state = convertToMaxtrix4x4(subInputEncrypt);
            displayMatrix2D(state);

            System.out.println("---------- Round 0 ----------");
            System.out.println("Used Key:");
            String[][] keyRound0 = new String[4][4];
            for(int row = 0; row < 4; row++) {
                for(int col = 0; col < 4; col++) {
                    keyRound0[row][col] = key[row][col];
                }
            }
            displayMatrix2D(keyRound0);
            state = addRoundKey(state, key);
            System.out.println("State after AddRoundKey:");
            displayMatrix2D(state);

            for (int i = 0; i < 12 - 1; i++) {
                System.out.println("---------- Round " + (i + 1) + " ----------");
                state = subBytes(state);
                System.out.println("State after SubBytes:");
                displayMatrix2D(state);
                state = shiftRows(state);
                System.out.println("State after ShiftRows:");
                displayMatrix2D(state);
                state = mixColumns(state);
                System.out.println("State after MixColumns:");
                displayMatrix2D(state);
                System.out.println("Used Key:");
                String[][] keyUsed = new String[4][4];
                for(int row = 0; row < 4; row++) {
                    for(int col = (i + 1) * 4; col < (i + 1) * 4 + 4; col++) {
                        keyUsed[row][col % 4] = key[row][col];
                    }
                }
                displayMatrix2D(keyUsed);
                state = addRoundKey(state, keyUsed);
                System.out.println("State after AddRoundKey:");
                displayMatrix2D(state);
            }

            System.out.println("---------- Round 12 ----------");
            state = subBytes(state);
            System.out.println("State after SubBytes:");
            displayMatrix2D(state);
            state = shiftRows(state);
            System.out.println("State after ShiftRows:");
            displayMatrix2D(state);
            System.out.println("Used Key:");
            String[][] keyRound12 = new String[4][4];
            for(int row = 0; row < 4; row++) {
                for(int col = 48; col < 52; col++) {
                    keyRound12[row][col % 4] = key[row][col];
                }
            }
            displayMatrix2D(keyRound12);
            state = addRoundKey(state, keyRound12);
            System.out.println("State after AddRoundKey:");
            displayMatrix2D(state);

            String enCryptedText = "";
            System.out.println("Final State: ");
            displayMatrix2D(state);
            for(int col = 0; col < 4; col++) {
                for(int row = 0; row < 4; row++) {
                    enCryptedText += state[row][col];
                }
            }

            ciphertext += enCryptedText;
        }

        System.out.println("Ciphertext (HEX): " + ciphertext);
        // Chuyển sang Base64
        ciphertext = Base64.getEncoder().encodeToString(hexToByteArray(ciphertext));

        System.out.println("Ciphertext (BASE64): " + ciphertext);
        System.out.println();

        return ciphertext;
    }

    public static String decrypt_hex(String ciphertext, String inputKey) {
        System.out.println("=============== DECRYPT ===============");
        System.out.println("Key: " + inputKey);
        String[][] originalKey = convertToMaxtrix4x6(inputKey.getBytes());
        String[][] key = keyExpansion(originalKey);

        System.out.println("Ciphertext (HEX): " + ciphertext);

        if(ciphertext.length() % 16 != 0) {
            System.out.println("Đầu vào phải là bội số của 16. Hiện tại là " + ciphertext.length() / 2 + " byte!");
            return "Đầu vào không hợp lệ!";
        }
        String decryptedText = "";
        for(int v = 0; v < ciphertext.length(); v += 32) {
            System.out.println("********** Sub Block **********");
            String subCiphertext = ciphertext.substring(v, v + 32);
            System.out.println("Original State:");
            String[][] state = arrangeToMatrix4x4(subCiphertext);
            displayMatrix2D(state);

            System.out.println("---------- Round 0 ----------");
            System.out.println("Used Key:");
            String[][] keyRound0 = new String[4][4];
            for(int row = 0; row < 4; row++) {
                for(int col = 48; col < 52; col++) {
                    keyRound0[row][col % 4] = key[row][col];
                }
            }
            displayMatrix2D(keyRound0);
            state = addRoundKey(state, keyRound0);
            System.out.println("State after AddRoundKey:");
            displayMatrix2D(state);

            for (int i = 0; i < 12 - 1; i++) {
                System.out.println("---------- Round " + (i + 1) + " ----------");
                state = invShiftRows(state);
                System.out.println("State after InverseShiftRows:");
                displayMatrix2D(state);
                state = invSubBytes(state);
                System.out.println("State after InverseSubBytes:");
                displayMatrix2D(state);
                System.out.println("Used Key:");
                String[][] keyUsed = new String[4][4];
                for(int row = 0; row < 4; row++) {
                    for(int col = 48 - 4 * (i + 1); col < 48 - 4 * (i + 1) + 4; col++) {
                        keyUsed[row][col % 4] = key[row][col];
                    }
                }
                displayMatrix2D(keyUsed);
                state = addRoundKey(state, keyUsed);
                System.out.println("State after AddRoundKey:");
                displayMatrix2D(state);
                state = invMixColumns(state);
                System.out.println("State after InverseMixColumns:");
                displayMatrix2D(state);
            }

            System.out.println("---------- Round 12 ----------");
            state = invShiftRows(state);
            System.out.println("State after InverseShiftRows:");
            displayMatrix2D(state);
            state = invSubBytes(state);
            System.out.println("State after InverseSubBytes:");
            displayMatrix2D(state);
            System.out.println("Used Key:");
            String[][] keyRound12 = new String[4][4];
            for(int row = 0; row < 4; row++) {
                for(int col = 0; col < 4; col++) {
                    keyRound12[row][col] = key[row][col];
                }
            }
            displayMatrix2D(keyRound12);
            state = addRoundKey(state, keyRound12);
            System.out.println("State after AddRoundKey:");
            displayMatrix2D(state);
            System.out.println("Final state:");
            displayMatrix2D(state);

            decryptedText += matric4x4ToString(state);
        }
        System.out.println("Decripted Text: " + decryptedText);

        byte[] outputDecrypt  = hexToByteArray(decryptedText);
        for(byte b : outputDecrypt) {
            System.out.print(b + " ");
        }
        outputDecrypt = removePadding(outputDecrypt);
        String plaintext = "";
        System.out.println();
        for (byte b : outputDecrypt) {
            System.out.print(String.format("%02X", b) + " ");
            plaintext += String.format("%02X", b);
        }
        System.out.println();
        plaintext = hexToStringUTF8(plaintext);
        System.out.println("Plaintext: " + plaintext);

        return plaintext;
    }

    public static String decrypt_base64(String ciphertext, String inputKey) {
        System.out.println("=============== DECRYPT ===============");
        System.out.println("Key: " + inputKey);
        String[][] originalKey = convertToMaxtrix4x6(inputKey.getBytes());
        String[][] key = keyExpansion(originalKey);

        System.out.println("Ciphertext (BASE64): " + ciphertext);
        ciphertext = bytesToHex(Base64.getDecoder().decode(ciphertext));
        System.out.println("Ciphertext (HEX): " + ciphertext);

        if(ciphertext.length() % 16 != 0) {
            System.out.println("Đầu vào phải là bội số của 16. Hiện tại là " + ciphertext.length() / 2 + " byte!");
            return "Đầu vào không hợp lệ!";
        }
        String decryptedText = "";
        for(int v = 0; v < ciphertext.length(); v += 32) {
            System.out.println("********** Sub Block **********");
            String subCiphertext = ciphertext.substring(v, v + 32);
            System.out.println("Original State:");
            String[][] state = arrangeToMatrix4x4(subCiphertext);
            displayMatrix2D(state);

            System.out.println("---------- Round 0 ----------");
            System.out.println("Used Key:");
            String[][] keyRound0 = new String[4][4];
            for(int row = 0; row < 4; row++) {
                for(int col = 48; col < 52; col++) {
                    keyRound0[row][col % 4] = key[row][col];
                }
            }
            displayMatrix2D(keyRound0);
            state = addRoundKey(state, keyRound0);
            System.out.println("State after AddRoundKey:");
            displayMatrix2D(state);

            for (int i = 0; i < 12 - 1; i++) {
                System.out.println("---------- Round " + (i + 1) + " ----------");
                state = invShiftRows(state);
                System.out.println("State after InverseShiftRows:");
                displayMatrix2D(state);
                state = invSubBytes(state);
                System.out.println("State after InverseSubBytes:");
                displayMatrix2D(state);
                System.out.println("Used Key:");
                String[][] keyUsed = new String[4][4];
                for(int row = 0; row < 4; row++) {
                    for(int col = 48 - 4 * (i + 1); col < 48 - 4 * (i + 1) + 4; col++) {
                        keyUsed[row][col % 4] = key[row][col];
                    }
                }
                displayMatrix2D(keyUsed);
                state = addRoundKey(state, keyUsed);
                System.out.println("State after AddRoundKey:");
                displayMatrix2D(state);
                state = invMixColumns(state);
                System.out.println("State after InverseMixColumns:");
                displayMatrix2D(state);
            }

            System.out.println("---------- Round 12 ----------");
            state = invShiftRows(state);
            System.out.println("State after InverseShiftRows:");
            displayMatrix2D(state);
            state = invSubBytes(state);
            System.out.println("State after InverseSubBytes:");
            displayMatrix2D(state);
            System.out.println("Used Key:");
            String[][] keyRound12 = new String[4][4];
            for(int row = 0; row < 4; row++) {
                for(int col = 0; col < 4; col++) {
                    keyRound12[row][col] = key[row][col];
                }
            }
            displayMatrix2D(keyRound12);
            state = addRoundKey(state, keyRound12);
            System.out.println("State after AddRoundKey:");
            displayMatrix2D(state);
            System.out.println("Final state:");
            displayMatrix2D(state);

            decryptedText += matric4x4ToString(state);
        }
        System.out.println("Decripted Text: " + decryptedText);

        byte[] outputDecrypt  = hexToByteArray(decryptedText);
        for(byte b : outputDecrypt) {
            System.out.print(b + " ");
        }
        outputDecrypt = removePadding(outputDecrypt);
        String plaintext = "";
        System.out.println();
        for (byte b : outputDecrypt) {
            System.out.print(String.format("%02X", b) + " ");
            plaintext += String.format("%02X", b);
        }
        System.out.println();
        plaintext = hexToStringUTF8(plaintext);
        System.out.println("Plaintext: " + plaintext);

        return plaintext;
    }

    public static void main(String[] args) {
        String plaintext = "Phạm Việt Hoàng Minh";
        String key = "phamvietlong150415041504";
        String ciphertext = encrypt_base64(plaintext, key);
        decrypt_base64(ciphertext, key);
    }
}
