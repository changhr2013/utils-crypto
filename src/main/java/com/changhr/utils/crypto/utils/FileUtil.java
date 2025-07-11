package com.changhr.utils.crypto.utils;

import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class FileUtil {

    /**
     * 绝对路径判断正则
     */
    private static final Pattern PATTERN_PATH_ABSOLUTE = Pattern.compile("^[a-zA-Z]:([/\\\\].*)?");


    /**
     * 获取当前线程的 {@link ClassLoader}
     *
     * @return 当前线程的 class loader
     * @see Thread#getContextClassLoader()
     */
    public static ClassLoader getContextClassLoader() {
        if (System.getSecurityManager() == null) {
            return Thread.currentThread().getContextClassLoader();
        } else {
            // 绕开权限检查
            return AccessController.doPrivileged(
                    (PrivilegedAction<ClassLoader>) () -> Thread.currentThread().getContextClassLoader());
        }
    }

    /**
     * 获取系统 {@link ClassLoader}
     *
     * @return 系统 {@link ClassLoader}
     * @see ClassLoader#getSystemClassLoader()
     */
    public static ClassLoader getSystemClassLoader() {
        if (System.getSecurityManager() == null) {
            return ClassLoader.getSystemClassLoader();
        } else {
            // 绕开权限检查
            return AccessController.doPrivileged(
                    (PrivilegedAction<ClassLoader>) ClassLoader::getSystemClassLoader);
        }
    }

    /**
     * 获取 {@link ClassLoader}<br>
     * 获取顺序如下：<br>
     *
     * <pre>
     * 1、获取当前线程的 ContextClassLoader
     * 2、获取当前类对应的 ClassLoader
     * 3、获取系统 ClassLoader（{@link ClassLoader#getSystemClassLoader()}）
     * </pre>
     *
     * @return 类加载器
     */
    public static ClassLoader getClassLoader() {
        ClassLoader classLoader = getContextClassLoader();
        if (classLoader == null) {
            classLoader = FileUtil.class.getClassLoader();
            if (null == classLoader) {
                classLoader = getSystemClassLoader();
            }
        }
        return classLoader;
    }

    /**
     * 从 URL 对象中获取不被编码的路径 Path<br>
     * 对于本地路径，URL 对象的 getPath 方法对于包含中文或空格时会被编码，导致本读路径读取错误。<br>
     * 此方法将 URL 转为 URI 后获取路径用于解决路径被编码的问题
     *
     * @param url {@link URL}
     * @return 路径
     */
    public static String getDecodedPath(URL url) {
        if (null == url) {
            return null;
        }

        String path = null;
        try {
            // URL 对象的 getPath 方法对于包含中文或空格的问题
            path = toURI(url.toString()).getPath();
        } catch (RuntimeException e) {
            // ignore
        }
        return (null != path) ? path : url.getPath();
    }

    /**
     * 是否空白符 <br>
     * 空白符包括空格、制表符、全角空格和不间断空格 <br>
     *
     * @param c 字符
     * @return 是否空白符
     */
    public static boolean isBlankChar(char c) {
        return isBlankChar((int) c);
    }

    /**
     * 是否空白符 <br>
     * 空白符包括空格、制表符、全角空格和不间断空格 <br>
     *
     * @param c 字符
     * @return 是否空白符
     */
    public static boolean isBlankChar(int c) {
        return Character.isWhitespace(c)
                || Character.isSpaceChar(c)
                || c == '\ufeff'
                || c == '\u202a'
                || c == '\u0000'
                // issue#I5UGSQ，Hangul Filler
                || c == '\u3164'
                // Braille Pattern Blank
                || c == '\u2800'
                // MONGOLIAN VOWEL SEPARATOR
                || c == '\u180e';
    }

    /**
     * 按照断言，除去字符串头尾部的断言为真的字符，如果字符串是 {@code null}，依然返回 {@code null}。
     *
     * @param str       要处理的字符串
     * @param mode      {@code -1} 表示 trimStart，{@code 0} 表示 trim 全部， {@code 1} 表示 trimEnd
     * @param predicate 断言是否过掉字符，返回 {@code true} 表述过滤掉，{@code false} 表示不过滤
     * @return 除去指定字符后的的字符串，如果原字串为 {@code null}，则返回 {@code null}
     */
    public static String trim(CharSequence str, int mode, Predicate<Character> predicate) {
        String result;
        if (str == null) {
            result = null;
        } else {
            int length = str.length();
            int start = 0;
            int end = length;// 扫描字符串头部
            if (mode <= 0) {
                while ((start < end) && (predicate.test(str.charAt(start)))) {
                    start++;
                }
            }// 扫描字符串尾部
            if (mode >= 0) {
                while ((start < end) && (predicate.test(str.charAt(end - 1)))) {
                    end--;
                }
            }
            if ((start > 0) || (end < length)) {
                result = str.toString().substring(start, end);
            } else {
                result = str.toString();
            }
        }

        return result;
    }

    /**
     * 转字符串为 URI
     *
     * @param location 字符串路径
     * @return URI
     */
    public static URI toURI(String location) throws RuntimeException {
        try {
            return new URI((null == location) ? null : trim(location, 0, FileUtil::isBlankChar));
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 获取标准的绝对路径
     *
     * @param file 文件
     * @return 绝对路径
     */
    public static String getAbsolutePath(File file) {
        if (file == null) {
            return null;
        }

        try {
            return file.getCanonicalPath();
        } catch (IOException e) {
            return file.getAbsolutePath();
        }
    }

    /**
     * 给定路径已经是绝对路径 <br>
     * 此方法并没有针对路径做标准化，建议先标准化路径后判断 <br>
     * 绝对路径判断条件是：
     * <ul>
     *     <li> 以 / 开头的路径 </li>
     *     <li> 满足类似于 c:/xxxxx，其中祖母随意，不区分大小写 </li>
     *     <li> 满足类似于 d:\xxxxx，其中祖母随意，不区分大小写 </li>
     * </ul>
     *
     * @param path 需要检查的 Path
     * @return 是否已经是绝对路径
     */
    public static boolean isAbsolutePath(String path) {
        if (StrUtil.isEmpty(path)) {
            return false;
        }

        // 给定的路径已经是绝对路径了
        return '/' == path.charAt(0) || PATTERN_PATH_ABSOLUTE.matcher(path).matches();
    }

    /**
     * 判断是否为目录，如果 path 为 null，则返回 false
     *
     * @param path 文件路径
     * @return 如果为目录 true
     */
    public static boolean isDirectory(String path) {
        return (null != path) && file(path).isDirectory();
    }

    /**
     * 判断是否为目录，如果 file 为 null，则返回 false
     *
     * @param file 文件
     * @return 如果为目录 true
     */
    public static boolean isDirectory(File file) {
        return (null != file) && file.isDirectory();
    }

    /**
     * 判断是否为文件，如果 path 为 null，则返回 false
     *
     * @param path 文件路径
     * @return 如果为文件 true
     */
    public static boolean isFile(String path) {
        return (null != path) && file(path).isFile();
    }

    /**
     * 判断是否为文件，如果 file 为 null，则返回 false
     *
     * @param file 文件
     * @return 如果为文件 true
     */
    public static boolean isFile(File file) {
        return (null != file) && file.isFile();
    }

    /**
     * 检查父完整路径是否为自路径的前半部分，如果不是说明不是子路径，可能存在 slip 注入。
     * <p>
     * 见 http://blog.nsfocus.net/zip-slip-2/
     *
     * @param parentFile 父文件或目录
     * @param file       子文件或目录
     * @return 子文件或目录
     * @throws IllegalArgumentException 检查创建的子文件不在父目录中抛出此异常
     */
    public static File checkSlip(File parentFile, File file) throws IllegalArgumentException {
        if (null != parentFile && null != file) {
            if (false == isSub(parentFile, file)) {
                throw new IllegalArgumentException("New file is outside of the parent dir: " + file.getName());
            }
        }
        return file;
    }

    /**
     * 判断给定的目录是否为给定文件或文件夹的子目录
     *
     * @param parent 父目录
     * @param sub    子目录
     * @return 子目录是否为父目录的子目录
     * @since 4.5.4
     */
    public static boolean isSub(File parent, File sub) {
        if (null == parent || null == sub) {
            throw new IllegalArgumentException("parent file or child file cannot be null");
        }
        return isSub(parent.toPath(), sub.toPath());
    }

    /**
     * 判断给定的目录是否为给定文件或文件夹的子目录
     *
     * @param parent 父目录
     * @param sub    子目录
     * @return 子目录是否为父目录的子目录
     * @since 5.5.5
     */
    public static boolean isSub(Path parent, Path sub) {
        return toAbsNormal(sub).startsWith(toAbsNormal(parent));
    }

    /**
     * 将 Path 路径转换为标准的绝对路径
     *
     * @param path 文件或目录 Path
     * @return 转换后的 Path
     */
    public static Path toAbsNormal(Path path) {
        if (null == path) {
            throw new IllegalArgumentException("path cannot be null");
        }
        return path.toAbsolutePath().normalize();
    }

    /**
     * 创建 File 对象，自动识别相对或绝对路径，相对路径将自动从 ClassPath 下寻找
     *
     * @param path 相对 ClassPath 的目录或者绝对路径目录
     * @return File
     */
    public static File file(String path) {
        if (null == path) {
            return null;
        }
        return new File(path);
    }

    /**
     * 创建 File 对象 <br>
     * 此方法会检查 slip 漏洞，漏洞说明见 http://blog.nsfocus.net/zip-slip-2/
     *
     * @param parent 父目录
     * @param path   文件路径
     * @return File
     */
    public static File file(String parent, String path) {
        return file(new File(parent), path);
    }

    /**
     * 创建 File 对象 <br>
     * 根据的路径构建文件，在 Win 下直接构建，在 Linux 下拆分路径单独构建
     * 此方法会检查 slip 漏洞，漏洞说明见 http://blog.nsfocus.net/zip-slip-2/
     *
     * @param parent 父文件对象
     * @param path   文件路径
     * @return File
     */
    public static File file(File parent, String path) {
        if (StrUtil.isBlank(path)) {
            throw new NullPointerException("File path is blank!");
        }
        return checkSlip(parent, buildFile(parent, path));
    }

    /**
     * 根据压缩包中的路径构建目录结构，在 Windows 下直接构建，在 Linux 下拆分路径单独构建
     *
     * @param outFile  最外部路径
     * @param fileName 文件名，可以包含路径
     * @return 文件或目录
     */
    private static File buildFile(File outFile, String fileName) {
        // 替换 Windows 路径分隔符为 Linux 路径分隔符，便于统一处理
        fileName = fileName.replace('\\', '/');
        if (false == isWindows()
                // 检查文件名中是否包含 "/"，不考虑以 "/" 结尾的情况
                && fileName.lastIndexOf('/', fileName.length() - 2) > 0) {
            // 在 Linux 下多层目录创建存在问题，/ 会被当成文件名的一部分，此处做处理
            // 使用 / 拆分路径（zip 中无 \），级联创建父目录
            final List<String> pathParts = Arrays.stream(fileName.split("/")).collect(Collectors.toList());
            final int lastPartIndex = pathParts.size() - 1;// 目录个数
            for (int i = 0; i < lastPartIndex; i++) {
                // 由于路径拆分，slip 不检查，在最后一步检查
                outFile = new File(outFile, pathParts.get(i));
            }
            // noinspection ResultOfMethodCallIgnored
            outFile.mkdirs();
            // 最后一个部分如果非空，作为文件名
            fileName = pathParts.get(lastPartIndex);
        }
        return new File(outFile, fileName);
    }

    /**
     * 是否为 Windows 环境
     *
     * @return 是否为 Windows 环境
     */
    public static boolean isWindows() {
        return '\\' == File.separatorChar;
    }

    /**
     * 通过多层目录参数创建文件 <br>
     * 此方法会检查 slip 漏洞，漏洞说明见 {@code http://blog.nsfocus.net/zip-slip-2/}
     *
     * @param directory 父目录
     * @param names     元素名（多层目录名），由外到内依次传入
     * @return the file 文件
     */
    public static File file(File directory, String... names) {
        if (null == directory) {
            throw new IllegalArgumentException("directory must not be null");
        }
        if (names == null || names.length == 0) {
            return directory;
        }

        File file = directory;
        for (String name : names) {
            if (null != name) {
                file = file(file, name);
            }
        }
        return file;
    }

    /**
     * 通过多层目录创建文件
     * <p>
     * 元素名（多层目录名）
     *
     * @param names 多层文件的文件名，由外到内依次传入
     * @return the file 文件
     */
    public static File file(String... names) {

        if (names == null || names.length == 0) {
            return null;
        }

        File file = null;
        for (String name : names) {
            if (file == null) {
                file = file(name);
            } else {
                file = file(file, name);
            }
        }
        return file;
    }

    /**
     * 创建 File 对象
     *
     * @param uri 文件 URI
     * @return File
     */
    public static File file(URI uri) {
        if (uri == null) {
            throw new NullPointerException("File uri is null!");
        }
        return new File(uri);
    }

    /**
     * 判断文件是否存在，如果 path 为 null，则返回 false
     *
     * @param path 文件路径
     * @return 如果存在返回 true
     */
    public static boolean exist(String path) {
        return (null != path) && file(path).exists();
    }

    /**
     * 判断文件是否存在，如果 file 为 null，则返回 false
     *
     * @param file 文件
     * @return 如果存在返回 true
     */
    public static boolean exist(File file) {
        return (null != file) && file.exists();
    }


    /**
     * 是否存在匹配文件
     *
     * @param directory 文件夹路径
     * @param regexp    文件夹中所包含文件名的正则表达式
     * @return 如果存在匹配文件返回 true
     */
    public static boolean exist(String directory, String regexp) {
        final File file = new File(directory);
        if (false == file.exists()) {
            return false;
        }

        final String[] fileList = file.list();
        if (fileList == null) {
            return false;
        }

        for (String fileName : fileList) {
            if (fileName.matches(regexp)) {
                return true;
            }

        }
        return false;
    }

    /**
     * 创建文件及其父目录，如果这个文件存在，直接返回这个文件 <br>
     * 此方法不对 File 对象类型做判断，如果 File 不存在，无法判断其类型
     *
     * @param path 相对 ClassPath 的目录或者绝对路径目录，使用 POSIX 风格
     * @return 文件，若路径为 null，返回 null
     */
    public static File touch(String path) throws IOException {
        if (path == null) {
            return null;
        }
        return touch(file(path));
    }

    /**
     * 创建文件及其父目录，如果这个文件存在，直接返回这个文件 <br>
     * 此方法不对 File 对象类型做判断，如果 File 不存在，无法判断其类型
     *
     * @param file 文件对象
     * @return 文件，若路径为 null，返回 null
     */
    public static File touch(File file) throws IOException {
        if (null == file) {
            return null;
        }
        if (false == file.exists()) {
            mkParentDirs(file);
            try {
                // noinspection ResultOfMethodCallIgnored
                file.createNewFile();
            } catch (Exception e) {
                throw new IOException(e);
            }
        }
        return file;
    }

    /**
     * 创建文件及其父目录，如果这个文件存在，直接返回这个文件 <br>
     * 此方法不对 File 对象类型做判断，如果 File 不存在，无法判断其类型
     *
     * @param parent 父文件对象
     * @param path   文件路径
     * @return File
     */
    public static File touch(File parent, String path) throws IOException {
        return touch(file(parent, path));
    }

    /**
     * 创建文件及其父目录，如果这个文件存在，直接返回这个文件 <br>
     * 此方法不对 File 对象类型做判断，如果 File 不存在，无法判断其类型
     *
     * @param parent 父文件对象
     * @param path   文件路径
     * @return File
     */
    public static File touch(String parent, String path) throws IOException {
        return touch(file(parent, path));
    }

    /**
     * 创建所给文件或目录的父目录
     *
     * @param file 文件或目录
     * @return 父目录
     */
    public static File mkParentDirs(File file) {
        if (null == file) {
            return null;
        }
        return mkdir(getParent(file, 1));
    }

    /**
     * 创建文件夹，会递归自动创建其不存在的父文件夹，如果存在直接返回此文件夹 <br>
     * 此方法不对 File 对象类型做判断，如果 File 不存在，无法判断其类型 <br>
     *
     * @param dir 目录
     * @return 创建的目录
     */
    public static File mkdir(File dir) {
        if (dir == null) {
            return null;
        }
        if (false == dir.exists()) {
            mkdirsSafely(dir, 5, 1);
        }
        return dir;
    }

    /**
     * 安全地级联创建目录 (确保并发环境下能创建成功)
     *
     * <pre>
     *     并发环境下，假设 test 目录不存在，如果线程 A mkdirs "test/A" 目录，线程 B mkdirs "test/B"目录，
     *     其中一个线程可能会失败，进而导致以下代码抛出 FileNotFoundException 异常
     *
     *     file.getParentFile().mkdirs(); // 父目录正在被另一个线程创建中，返回 false
     *     file.createNewFile(); // 抛出 IO 异常，因为该线程无法感知到父目录已被创建
     * </pre>
     *
     * @param dir         待创建的目录
     * @param tryCount    最大尝试次数
     * @param sleepMillis 线程等待的毫秒数
     * @return true 表示创建成功，false 表示创建失败
     */
    public static boolean mkdirsSafely(File dir, int tryCount, long sleepMillis) {
        if (dir == null) {
            return false;
        }
        if (dir.isDirectory()) {
            return true;
        }
        for (int i = 1; i <= tryCount; i++) { // 高并发场景下，可以看到 i 处于 1 ~ 3 之间
            // 如果文件已存在，也会返回 false，所以该值不能作为是否能创建的依据，因此不对其进行处理
            // noinspection ResultOfMethodCallIgnored
            dir.mkdirs();
            if (dir.exists()) {
                return true;
            }

            if (sleepMillis > 0) {
                try {
                    Thread.sleep(sleepMillis);
                } catch (InterruptedException e) {
                    // ignore exception
                }
            }
        }
        return dir.exists();
    }

    /**
     * 获取指定层级的父路径
     *
     * <pre>
     * getParent(file("d:/aaa/bbb/cc/ddd", 0)) -》 "d:/aaa/bbb/cc/ddd"
     * getParent(file("d:/aaa/bbb/cc/ddd", 2)) -》 "d:/aaa/bbb"
     * getParent(file("d:/aaa/bbb/cc/ddd", 4)) -》 "d:/"
     * getParent(file("d:/aaa/bbb/cc/ddd", 5)) -》 null
     * </pre>
     *
     * @param file  目录或文件
     * @param level 层级
     * @return 路径 File，如果不存在返回 null
     * @since 4.1.2
     */
    public static File getParent(File file, int level) {
        if (level < 1 || null == file) {
            return file;
        }

        File parentFile;
        try {
            parentFile = file.getCanonicalFile().getParentFile();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        if (1 == level) {
            return parentFile;
        }
        return getParent(parentFile, level - 1);
    }

    /**
     * 创建父文件夹，如果存在直接返回此文件夹
     *
     * @param path 文件夹路径，使用 POSIX 格式，无论哪个平台
     * @return 创建的目录
     */
    public static File mkParentDirs(String path) {
        if (path == null) {
            return null;
        }
        return mkParentDirs(file(path));
    }

    /**
     * 将 String 写入文件，覆盖模式，字符集为 UTF-8
     *
     * @param content 写入的内容
     * @param path    文件路径
     * @return 写入的文件
     */
    public static File writeUtf8String(String content, String path) throws IOException {
        return writeString(content, path, StandardCharsets.UTF_8);
    }

    /**
     * 将 String 写入文件，覆盖模式，字符集为 UTF-8
     *
     * @param content 写入的内容
     * @param file    文件
     * @return 写入的文件
     */
    public static File writeUtf8String(String content, File file) throws IOException {
        return writeString(content, file, StandardCharsets.UTF_8);
    }

    /**
     * 将 String 写入文件，覆盖模式
     *
     * @param content 写入的内容
     * @param path    文件路径
     * @param charset 字符集
     * @return 写入的文件
     */
    public static File writeString(String content, String path, Charset charset) throws IOException {
        return writeString(content, touch(path), charset);
    }

    /**
     * 将 String 写入文件，覆盖模式
     *
     * @param content 写入的内容
     * @param file    文件
     * @param charset 字符集
     * @return 被写入的文件
     */
    public static File writeString(String content, File file, Charset charset) throws IOException {
        BufferedWriter writer = null;
        try {
            try {
                writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(FileUtil.touch(file), false), charset));
            } catch (Exception e) {
                throw new IOException(e);
            }
            writer.write(content);
            writer.flush();
        } finally {
            if (null != writer) {
                try {
                    writer.close();
                } catch (Exception e) {
                    // 静默关闭
                }
            }
        }
        return file;
    }


    /**
     * 读取文件所有内容为 UTF-8 字符串 (字符串路径)
     *
     * @param pathStr 文件路径字符串
     * @return 文件内容
     * @throws IOException 如果读取失败
     */
    public static String readUtf8String(String pathStr) throws IOException {
        return readUtf8String(Paths.get(pathStr));
    }

    /**
     * 读取文件所有内容为 UTF-8 字符串
     *
     * @param path 文件路径
     * @return 文件内容
     * @throws IOException 如果读取失败
     */
    public static String readUtf8String(Path path) throws IOException {
        return readString(path, StandardCharsets.UTF_8);
    }

    /**
     * 读取文件所有内容为字符串 (基于 NIO，Java 8 兼容)
     *
     * @param path    文件路径
     * @param charset 字符集
     * @return 文件内容
     * @throws IOException 如果读取失败
     */
    public static String readString(Path path, Charset charset) throws IOException {
        Objects.requireNonNull(path, "文件路径不能为 null");
        Charset actualCharset = charset != null ? charset : StandardCharsets.UTF_8;

        // Java 8 兼容的实现方式
        byte[] bytes = Files.readAllBytes(path);
        return new String(bytes, actualCharset);
    }

    /**
     * 读取文件所有行 (UTF-8)
     *
     * @param path 文件路径
     * @return 行的 Stream
     * @throws IOException 如果读取失败
     */
    public static Stream<String> linesUtf8(Path path) throws IOException {
        return lines(path, StandardCharsets.UTF_8);
    }

    /**
     * 读取文件所有行
     *
     * @param path    文件路径
     * @param charset 字符集
     * @return 行的 Stream
     * @throws IOException 如果读取失败
     */
    public static Stream<String> lines(Path path, Charset charset) throws IOException {
        Objects.requireNonNull(path, "文件路径不能为 null");
        Charset actualCharset = charset != null ? charset : StandardCharsets.UTF_8;
        return Files.lines(path, actualCharset);
    }

    /**
     * 写入行列表到文件
     *
     * @param path    文件路径
     * @param lines   行列表
     * @param charset 字符集
     * @throws IOException 如果写入失败
     */
    public static void writeLines(Path path, Iterable<? extends CharSequence> lines, Charset charset) throws IOException {
        Objects.requireNonNull(path, "文件路径不能为 null");
        Objects.requireNonNull(lines, "行列表不能为 null");
        Charset actualCharset = charset != null ? charset : StandardCharsets.UTF_8;
        Files.write(path, lines, actualCharset);
    }

    /**
     * 写入行列表到文件 (UTF-8)
     *
     * @param path  文件路径
     * @param lines 行列表
     * @throws IOException 如果写入失败
     */
    public static void writeUtf8Lines(Path path, Iterable<? extends CharSequence> lines) throws IOException {
        writeLines(path, lines, StandardCharsets.UTF_8);
    }

    /**
     * 复制文件
     *
     * @param source 源文件路径
     * @param target 目标文件路径
     * @throws IOException 如果复制失败
     */
    public static void copyFile(Path source, Path target) throws IOException {
        Objects.requireNonNull(source, "源文件路径不能为null");
        Objects.requireNonNull(target, "目标文件路径不能为null");
        Files.copy(source, target);
    }

    /**
     * 检查文件是否存在且可读
     *
     * @param path 文件路径
     * @return 是否存在且可读
     */
    public static boolean isReadable(Path path) {
        return path != null && Files.exists(path) && Files.isReadable(path);
    }

    /**
     * 检查文件是否存在且可写
     *
     * @param path 文件路径
     * @return 是否存在且可写
     */
    public static boolean isWritable(Path path) {
        return path != null && Files.exists(path) && Files.isWritable(path);
    }

    /**
     * 获取文件大小
     *
     * @param path 文件路径
     * @return 文件大小（字节）
     * @throws IOException 如果获取失败
     */
    public static long size(Path path) throws IOException {
        Objects.requireNonNull(path, "文件路径不能为null");
        return Files.size(path);
    }
}
