package com.ias101.lab1.security;

import com.ias101.lab1.database.util.DBUtil;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.regex.Pattern;

/**
 * Authentication class for user validation
 */
public class Authenticator {
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{3,20}$");
    private static final Pattern PASSWORD_PATTERN = Pattern.compile("^[a-zA-Z0-9@#$%^&+=!?]{6,30}$");

    /**
     * Validates username and password using regular expressions.
     * @param username The username input
     * @param password The password input
     * @return boolean Returns true if valid, false otherwise
     */
    private static boolean isValidInput(String username, String password) {
        return USERNAME_PATTERN.matcher(username).matches() && PASSWORD_PATTERN.matcher(password).matches();
    }

    /**
     * Authenticates a user by checking username and password against the database.
     *
     * @param username The username to authenticate
     * @param password The password to authenticate
     * @return boolean Returns true if authentication is successful, false otherwise
     * @throws RuntimeException if there is a SQL error during authentication
     */
    public static boolean authenticateUser(String username, String password) {
        if (!isValidInput(username, password)) {
            System.err.println("Invalid input detected. Possible SQL Injection attempt.");
            return false;
        }

        String query = "SELECT * FROM user_data WHERE username = ? AND password = ?";

        try (var conn = DBUtil.connect("jdbc:sqlite:src/main/resources/database/sample.db", "root", "root");
             PreparedStatement statement = conn.prepareStatement(query)) {

            statement.setString(1, username);
            statement.setString(2, password);

            try (ResultSet rs = statement.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            throw new RuntimeException("Database error during authentication.", e);
        }
    }
}
