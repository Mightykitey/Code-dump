<?php
// Function to check if a given email already exists in the 'users' table
function only_users($conn, $email)
{
    try {
        // Prepare SQL statement to search for a user by email
        $sql = "SELECT email FROM users WHERE email = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(1, $email);  // Bind email parameter
        $stmt->execute();             // Execute the SQL query

        $result = $stmt->fetch(PDO::FETCH_ASSOC);  // Fetch one matching row

        // Return true if a match is found, false otherwise
        return $result ? true : false;

    } catch (PDOException $e) {
        // Log and rethrow database errors
        error_log("Error in user lookup: " . $e->getMessage());
        throw $e;
    }
}


// Function to insert a new user record into the database
function new_users($conn, $post)
{
    try {
        // SQL query with placeholders for inserting new user data
        $sql = "INSERT INTO users (fname, lname, dob, email, pwd) VALUES (?,?,?,?,?)";
        $stmt = $conn->prepare($sql);

        // Bind form data to the SQL query
        $stmt->bindParam(1, $post['fname']);
        $stmt->bindParam(2, $post['lname']);
        $stmt->bindParam(3, $post['dob']);
        $stmt->bindParam(4, $post['email']);

        // Securely hash password before storing
        $hpwd = password_hash($post['pwd'], PASSWORD_DEFAULT);
        $stmt->bindParam(5, $hpwd);

        // Execute the insert query
        $stmt->execute();
        $conn = null; // Close connection (optional)
        return true;

    } catch (PDOException $e) {
        // Log and rethrow database-related exceptions
        error_log('Database error: ' . $e->getMessage());
        throw new Exception('Database error: ' . $e->getMessage());
    } catch (Exception $e) {
        // Log and rethrow any other type of error
        error_log('Error: ' . $e->getMessage());
        throw new Exception('Error: ' . $e->getMessage());
    }
}


// Function to show and clear a session-based user message
function user_message()
{
    if (isset($_SESSION['usermessage'])) {
        $message = "<p>" . $_SESSION['usermessage'] . "</p>";
        unset($_SESSION['usermessage']); // Remove message after displaying
        return $message;
    } else {
        return "";
    }
}

// Function to record an audit log entry (tracks user activity)
function audititor($conn, $usrid, $code, $ldesc)
{
    $sql = "INSERT INTO audit (date, userid, code, longdesc) VALUES (?,?,?,?)";
    $stmt = $conn->prepare($sql);

    $date = date("Y-m-d");  // Current date
    $stmt->bindParam(1, $date);
    $stmt->bindParam(2, $usrid);
    $stmt->bindParam(3, $code);
    $stmt->bindParam(4, $ldesc);

    $stmt->execute();
    $conn = null;
    return true;
}


// Function to check if password session variable contains an error
function hasPassword($string)
{
    if (!str_contains($_SESSION['password'], "ERROR")) {
        $string = "USER MESSAGE: " . $_SESSION['password'];
        return true;
    } else {
        $string = "USER MESSAGE: " . $_SESSION['password'];
        return false;
    }
}
