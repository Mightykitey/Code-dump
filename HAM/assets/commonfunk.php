<?php
// Function to show and clear a session-based user message
function user_message()
{
    if (isset($_SESSION['user_message'])) {
        $message = "<p>" . $_SESSION['user_message'] . "</p>";
        unset($_SESSION['user_message']); // Remove message after displaying
        return $message;
    } else {
        return "";
    }
}

function new_user($conn)
{
    $sql = "INSERT INTO user (fname, lname, dob, email, pwd) VALUES (?,?,?,?,?)";
    $stmt = $conn->prepare($sql);

    $stmt->bindParam(1, $_POST['fname']);
    $stmt->bindParam(2, $_POST['lname']);
    $stmt->bindParam(3, $_POST['dob']);
    $stmt->bindParam(4, $_POST['email']);
    $pwd = password_hash($_POST['pwd'], PASSWORD_DEFAULT);
    $stmt->bindParam(5, $pwd);

    $stmt->execute();
    $conn = null;
    return true;
}

// Function to check if a given email already exists in the 'user' table
function only_user($conn, $email){ //get the user id
    $sql = "SELECT userid FROM user WHERE email = ?"; //set up the sql statement
    $stmt = $conn->prepare($sql); //prepares
    $stmt->bindParam(1, $email);
    $stmt->execute(); //run the sql code

    $result = $stmt->fetch(PDO::FETCH_ASSOC);  //brings back results
    return $result["userid"];
}

function login($conn, $post)
{
    $sql = "SELECT viewid, pwd FROM viewer WHERE email = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(1, $_POST);
    $stmt->execute();

    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    $conn = null;

    // Return user data if found, otherwise false
    return $result ? $result : false;
}

// Function to record an audit log entry (tracks user activity)
function audititor($conn, $userid, $code, $long){  # on doing any action, auditor is called and the action recorded
    $sql = "INSERT INTO audit (date, userid, code, auditdescrip) VALUES (?, ?, ?, ?)";  //prepare the sql to be sent
    $stmt = $conn->prepare($sql); //prepare to sql
    $tmptime = time();  // prepared the time here as not supposed to pass it directly as a bound parameter.
    $stmt->bindParam(1, $tmptime);  //bind parameters for security
    $stmt->bindParam(2, $userid);
    $stmt->bindParam(3, $code);
    $stmt->bindParam(4, $long);

    $stmt->execute();  //run the query to insert
    $conn = null;  // closes the connection so cant be abused.
    return true; // Registration successful
}


/*function commit_bookimg($conn, $epoch)
{
    $sql = "INSERT INTO booking (userid, staffid, appdate, bookdon) VALUES (?,?,?,?)";
    $stmt = $conn->prepare($sql);

    $stmt->bindParam(1, $_SESSION['usrid']);
    $stmt->bindParam(2, $_POST['staff']);
    $stmt->bindParam(3, $epoch);

    $temp = time(); // Record booking creation time
    $stmt->bindParam(4, $temp);

    $stmt->execute();
    $conn = null;
    return true;
}*/

// Function to get all appointments for the logged-in patient
/*function apt_getter($conn){
    $sql = "SELECT b.bookid, b.appdate, b.bookdon, s.job, s.fname, s.sname
from book b JOIN staff s ON b.staffid = s.staffid WHERE b.userid = ? ORDER BY b.appdate ASC";
    $stmt = $conn->prepare($sql);

    $stmt->bindParam(1, $_SESSION["userid"]);
    $stmt->execute();
    $result = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $conn = null;
    if($result){
        return $result;
    } else {
        return false;
    }

}*/

