<?php
// Function to check if a given email already exists in the 'users' table
function only_user($conn, $email)
{  # At registration checks to make sure that no user already matches
    $sql = "SELECT email FROM user WHERE email = ?"; //set up the sql statement
    $stmt = $conn->prepare($sql); //prepares
    $stmt->bindParam(1, $email);
    $stmt->execute(); //run the sql code
    $result = $stmt->fetch(PDO::FETCH_ASSOC);  //brings back results
    if ($result) {  # if a user is returned
        return false; # return false so y
    } else {
        return true;
    }
}

// Function to insert a new user record into the database
function new_user($conn, $post)
{
    try {
        // SQL query with placeholders for inserting new user data
        $sql = "INSERT INTO user (fname, lname, dob, email, pwd) VALUES (?,?,?,?,?)";
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
function user_message (){  # function to check for a user message and return echoable string
    if(isset($_SESSION['usermessage'])){  # checks to see if it is set
        if(str_contains($_SESSION['usermessage'],"ERROR")){  # if it's an error
            $message = "<p>".$_SESSION['usermessage']."<p>";  # formats string appropriately
        } else {  # if it's not an error
            $message = "<p>".$_SESSION['usermessage']."<p>";  # positive message given
        }
        unset($_SESSION['usermessage']);  # unsets the user message so it doesn't keep being displayed
    } else {
        $message = "";  # if no message has been set, returns empty string.
    }
    return $message;
}

// Function to record an audit log entry (tracks user activity)
/*
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
*/

// Function to check if password session variable contains an error
function pwd_checker($password){
$rules = array();

    $rules["1"] = lenchecker($password);
    $rules["2"] = capchecker($password);
    $rules["3"] = lowerchecker($password);
    $rules["4"] = specialchecker($password);
    $rules["5"] = "Rule 5 - " . numchecker($password). "Your Password must contain a number";
    $rules["6"] = "Rule 6 - " . specialcheckerfirst($password[0]). "First character cannot be a special character";
    $rules["7"] = "Rule 7 - " . specialcheckerfirst($password[strlen($password)]). "Last character cannot be a special character";
    $rules["8"] = pwdcontains($password);
    $rules["9"] = "Rule 9 - " . numchecker($password[0]). "Your password cannot start with a number";
    return $rules;
}

function pwdcontains($password){
    if(str_contains($password, "password") OR str_contains($password,"Password") OR str_contains($password, "PASSWORD")){
        return "Rule 8 - Fail: Your password should not contain the word password";
    } else {
        return "Rule 8 - Pass: Your password should not contain the word password";
    }
}

function specialcheckerfirst($password){
    if (preg_match('/[^a-zA-Z0-9]/', $password)) {
        return "Fail: ";
    } else {
        return "Pass: ";
    }
}

function numchecker($password){
    if (!preg_match('/[0-9]/', $password)) {
        if(strlen($password)==1){
            return "Pass: ";
        } else {
            return "Fail: ";
        }
    } else {
        return "Pass: ";
    }
}

function specialchecker($password){
    if (!preg_match('/[^a-zA-Z0-9]/', $password)) {
        return "Rule 4 - Fail: Your password must contain at least 1 Special Character";
    } else {
        return "Rule 4 - Pass: Your password must contain at least 1 Special Character";
    }
}

function lowerchecker($password){
    if (!preg_match('/[a-z]/', $password)) {
        return "Rule 3 - Fail: Your password must contain at least 1 lowercase letter";
    } else {
        return "Rule 3 - Pass: Your password must contain at least 1 lowercase letter";
    }
}

function capchecker($password){
    if (!preg_match('/[A-Z]/', $password)) {
        return "Rule 2 - Fail: Your password must contain at least 1 uppercase letter";
    } else {
        return "Rule 2 - Pass: Your password must contain at least 1 uppercase letter";
    }
}

function lenchecker($password){
    if(strlen($password) < 8){
        return "Rule 1 - FAIL: Your password is less than 8 characters";
    }
    else{
        return "Rule 1 - Pass: Your password is longer than 8 characters";
    }
}
function getnewuserid($conn, $email){  # upon registering, retrieves the userid from the system to audit.
    $sql = "SELECT userid FROM user WHERE email = ?"; //set up the sql statement
    $stmt = $conn->prepare($sql); //prepares
    $stmt->bindParam(1, $email);
    $stmt->execute(); //run the sql code
    $result = $stmt->fetch(PDO::FETCH_ASSOC);  //brings back results
    return $result["userid"];
}
