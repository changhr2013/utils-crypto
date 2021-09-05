package com.changhr.utils.crypto.utils;

/**
 * ZeroPadding 填充工具类
 *
 * @author changhr
 * @create 2020-09-17 10:54
 */
public class PaddingUtil {

    private PaddingUtil() {
    }

    /**
     * 根据 blockSize 为 data 做 ZeroPadding 处理
     *
     * @param data      数据
     * @param blockSize 块大小
     * @return 使用 ZeroPadding 补足块大小整数倍的原始数据
     */
    public static byte[] formatWithZeroPadding(byte[] data, final int blockSize) {
        final int length = data.length;
        final int remainLength = length % blockSize;

        if (remainLength > 0) {
            byte[] inputData = new byte[length + blockSize - remainLength];
            System.arraycopy(data, 0, inputData, 0, length);
            return inputData;
        }
        return data;
    }

    /**
     * 移除数据末尾的 ZeroPadding
     *
     * @param data      数据
     * @param blockSize 块大小
     * @return 移除 ZeroPadding 后的数据
     */
    public static byte[] removeZeroPadding(byte[] data, final int blockSize) {
        final int length = data.length;
        final int remainLength = length % blockSize;
        if (remainLength == 0) {
            // 解码后的数据正好是块大小的整数倍，说明可能存在补 0 的情况，去掉末尾所有的 0
            int i = length - 1;
            while (i >= 0 && 0 == data[i]) {
                i--;
            }
            byte[] outputData = new byte[i + 1];
            System.arraycopy(data, 0, outputData, 0, outputData.length);
            return outputData;
        }
        return data;
    }
}
