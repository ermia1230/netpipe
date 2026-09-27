package se.ermia.netpipe.config;

import java.util.Properties;

/**
 * Simple command-line argument parser for {@code --key=value} arguments.
 *
 * <p>Written by Peter Sjödin (KTH/IK2206).
 * Refactored by Ermia Ghaffari: added duplicate detection and improved error messages.</p>
 */
public class Arguments extends Properties {

    private static final long serialVersionUID = 1L;
    private final Properties argumentSpecs = new Properties();

    /**
     * Set a default value for an argument.
     */
    public void setDefault(String arg, String value) {
        setProperty(arg, value);
    }

    /**
     * Register an expected argument with a description of its value.
     */
    public void setArgumentSpec(String arg, String valueDescription) {
        argumentSpecs.setProperty(arg, valueDescription);
    }

    /**
     * Parse command-line arguments.
     *
     * @param args the command-line arguments array
     * @throws IllegalArgumentException if any argument is malformed or unknown
     */
    public void loadArguments(String[] args) {
        for (String argument : args) {
            if (!argument.startsWith("--")) {
                throw new IllegalArgumentException(
                        "Argument does not start with \"--\": " + argument);
            }
            String[] keyValue = argument.substring(2).split("=", 2);
            String key = keyValue[0];

            if (argumentSpecs.getProperty(key) == null) {
                throw new IllegalArgumentException("Unknown argument: \"" + key + "\"");
            }
            if (keyValue.length != 2 || keyValue[1].isEmpty()) {
                throw new IllegalArgumentException(
                        "Argument \"" + key + "\" requires a value");
            }
            if (containsKey(key) && !getProperty(key).equals(keyValue[1])) {
                throw new IllegalArgumentException(
                        "Duplicate argument: \"" + key + "\"");
            }
            setProperty(key, keyValue[1]);
        }
    }

    /**
     * Get the value of a parsed argument.
     */
    public String get(String arg) {
        return getProperty(arg);
    }
}
