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
    $sql = "INSERT INTO user (fname, lname, dob, email, pwd) VALUES (?,?,?,?,?)";
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
function only_user($conn, $email)
{
    $sql = "SELECT email FROM user WHERE email = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(1, $email);
    $stmt->execute();

    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    return $result ? true : false;
}

function login($conn, $post)
{
    $sql = "SELECT userid, pwd FROM user WHERE email = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(1, $post);
    $stmt->execute();

    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    $conn = null;

    // Return user data if found, otherwise false
    return $result ? $result : false;
}

// Function to record an audit log entry (tracks user activity)
function audititor($conn, $usrid, $code, $ldesc)
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
function commit_bookimg($conn, $epoch)
{
    $sql = "INSERT INTO booking (userid, techid, appdate, bookdon) VALUES (?,?,?,?)";
    $stmt = $conn->prepare($sql);

    $stmt->bindParam(1, $_SESSION['usrid']);
    $stmt->bindParam(2, $_POST['staff']);
    $stmt->bindParam(3, $epoch);

    $temp = time(); // Record booking creation time
    $stmt->bindParam(4, $temp);

    $stmt->execute();
    $conn = null;
    return true;
}

// Function to get all appointments for the logged-in user
function apt_getter($conn)
{
    $sql = "SELECT b.bookid, b.appdate, b.bookdon, s.job, s.fname, s.lname, s.rom 
            FROM booking b 
            JOIN techid s ON b.techid = s.techid 
            WHERE b.userid = ? 
            ORDER BY b.appdate ASC";

    $stmt = $conn->prepare($sql);
    $stmt->bindParam(1, $_SESSION['usrid']);
    $stmt->execute();

    $result = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $conn = null;

    // Return all appointments or false if none exist
    return $result ? $result : false;
}


// Function to cancel an appointment
function cancel_apt($conn, $aptid)
{
    $sql = "DELETE FROM booking WHERE bookid = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(1, $aptid);
    $stmt->execute();
    $conn = null;
    return true;
}


// Function to fetch one appointment by its ID
function apt_fetch($conn, $aptid)
{
    $SQL = "SELECT * FROM booking WHERE bookid = ?";
    $stmt = $conn->prepare($SQL);
    $stmt->bindParam(1, $aptid);
    $stmt->execute();

    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    $conn = null;
    return $result;
}


// Function to update appointment details (techid/time)
function apt_update($conn, $aptid, $aptime)
{
    $sql = "UPDATE booking SET techid = ?, appdate = ?, bookdon = ? WHERE bookid = ?";
    $stmt = $conn->prepare($sql);

    $stmt->bindParam(1, $_POST['techid']);
    $stmt->bindParam(2, $aptime);
    $stmt->bindParam(3, $aptid); // ⚠️ Possibly a bug: should bind bookdon, not aptid
    $stmt->execute();

    $conn = null;
    return true;
}


// Function to get a user's profile and audit records
function pro_getter($conn)
{
    $sql = "SELECT p.userid, p.fname, p.lname, p.dob, p.email, p.pwd, a.code, a.date, a.longdesc
            FROM users p 
            JOIN audit a ON p.userid = a.userid 
            WHERE p.userid = ? 
            ORDER BY a.date ASC";

    $stmt = $conn->prepare($sql);
    $stmt->bindParam(1, $_SESSION['usrid']);
    $stmt->execute();

    $result = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $conn = null;

    return $result ? $result : false;
}