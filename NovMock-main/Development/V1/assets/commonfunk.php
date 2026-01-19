<?php
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

function new_User($conn, $post)
{
    $sql = "INSERT INTO Users (fname, lname, dob, email, pwd) VALUES (?,?,?,?,?)";
    $stmt = $conn->prepare($sql);

    $stmt->bindParam(1, $post['fname']);
    $stmt->bindParam(2, $post['lname']);
    $stmt->bindParam(3, $post['dob']);
    $stmt->bindParam(4, $post['email']);

    $hpwd = password_hash($post['pwd'], PASSWORD_DEFAULT);
    $stmt->bindParam(5, $hpwd);

    $stmt->execute();
    $conn = null;
    return true;
}

// Function to check if a given email already exists in the 'user' table
function only_User($conn, $email)
{
    $sql = "SELECT email FROM Users WHERE email = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(1, $email);
    $stmt->execute();

    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    return $result ? true : false;
}

// Function to record an audit log entry (tracks user activity)
function audit($conn, $usrid, $code, $ldesc)
{
    $sql = "INSERT INTO audit (date, user_id, code, longdesc) VALUES (?,?,?,?)";
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
