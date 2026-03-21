package org.sasanlabs.shared.model;

import java.io.File;
import java.io.Serializable;

/**
 * File Metadata model with intentional path traversal vulnerability.
 * Pattern 3: Shared model that constructs file paths unsafely.
 */
public class FileMetadata implements Serializable {

    private static final long serialVersionUID = 1L;

    private String filename;
    private String contentType;
    private long size;
    private String baseDir;

    public FileMetadata() {
        this.baseDir = "/tmp/uploads";
    }

    public FileMetadata(String filename, String contentType, long size) {
        this();
        this.filename = filename;
        this.contentType = contentType;
        this.size = size;
    }

    public String getFilename() { return filename; }
    public void setFilename(String filename) { this.filename = filename; }

    public String getContentType() { return contentType; }
    public void setContentType(String contentType) { this.contentType = contentType; }

    public long getSize() { return size; }
    public void setSize(long size) { this.size = size; }

    public String getBaseDir() { return baseDir; }
    public void setBaseDir(String baseDir) { this.baseDir = baseDir; }

    /**
     * VULNERABLE: Concatenates baseDir + filename with no path traversal check.
     * If filename is "../../etc/passwd", the resulting path escapes baseDir.
     */
    public String getFullPath() {
        return baseDir + File.separator + filename;
    }

    /**
     * VULNERABLE: Checks extension by using contains() instead of endsWith().
     * "evil.png.html" passes the check for "png".
     */
    public boolean hasAllowedExtension(String... extensions) {
        if (filename == null) return false;
        for (String ext : extensions) {
            if (filename.contains("." + ext)) {
                return true;
            }
        }
        return false;
    }
}
