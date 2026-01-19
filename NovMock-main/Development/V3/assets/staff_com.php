<?php

function only_staff($conn,$email){
    try{
        $sql = "SELECT email FROM staff WHERE email = ?"; //set up the sql statement
        $stmt = $conn->prepare($sql);   //prepares
        $stmt->bindparam(1, $email);
        $stmt->execute();    //run the sql code

        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($result){
            return true;
        }else{
            return false;
        }

    }
    catch(PDOException $e){//catch error
        // Log the error (crucial!)
        error_log("There an error in the user table: " . $e->getMessage());
        // Throw the exception
        throw $e;   // Re-throw the exception
    }
}



// Function to insert a new user into the database
function new_staff($conn, $post)
{
    try {
        // Prepare an SQL statement with placeholders to insert new user data
        $sql = "INSERT INTO staff (fname, lname, job, email,pwd) VALUES (?,?,?,?,?)"; // Using a prepared statement for security
        $stmt = $conn->prepare($sql);  // Prepare the SQL statement to prevent SQL injection

        // Bind the form data to the prepared statement parameters
        $stmt->bindParam(1, $post['fname']); // Bind first name
        $stmt->bindParam(2, $post['lname']); // Bind last name
        $stmt->bindParam(3, $post['job']);   // Bind date of birth
        $stmt->bindParam(4, $post['email']); // Bind email

        // Hash the password using SHA-256 before storing it
        // Secure the password by hashing// Bind the hashed password, not the plain text
        $stmt->bindParam(5, password_hash($_POST['pwd'], PASSWORD_DEFAULT));// Execute the prepared statement to insert the data
        $stmt->execute();

        // Close the database connection after the operation (optional, but good practice)
        $conn = null;
        return true;
    } catch (PDOException $e) {
        // Log PDO-related errors (e.g., DB connection issues) without exposing details to the user
        error_log(' database error: ' . $e->getMessage());
        throw new Exception(' database error: ' . $e->getMessage());
    } catch (Exception $e) {
        // Catch any other general exceptions
        error_log(' error: ' . $e->getMessage());
        throw new Exception(' error: ' . $e->getMessage());
    }
}

function staff_message()
{
    if (isset($_SESSION['staffmessage'])) {
        $message = "<p>" . $_SESSION['staffmessage'] . "</p>";
        unset($_SESSION['staffmessage']);
        return $message;
    } else {
        return "";
    }
}



function S_audititor($conn, $stfid, $job, $long){
    $sql = "INSERT INTO saudit (job, date, desc, staff_id) VALUES (?,?,?,?)";
    $stmt = $conn->prepare($sql);
    $dte = date("Y-m-d");
    $stmt->bindParam(1, $stfid);
    $stmt->bindParam(2, $job);
    $stmt->bindParam(3, $dte);
    $stmt->bindParam(4, $long);


    $stmt->execute();
    $conn = null;
    return true;
}
function staff_login($conn, $post)
{
    try {
        $sql = "SELECT staffid, password FROM staff WHERE email  = ?"; //set up the sql statement. * get all the fields form teh user
        $stmt = $conn->prepare($sql);

        $stmt->bindParam(1, $post['email']);    // binds the parameters to executes to be more secure
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC); // brings back the results
        $conn = null;

        if ($result) {
            return $result;
        } else {
            $_SESSION["usermessage"] = 'staff NOT FOUND';
            header("location: index.php");
            exit();
        }


    } catch (Exception $e) {
        $_SESSION["usermessage"] = 'User login' . $e->getMessage();
        header("location: index.php");
        exit();
    }

}


function stfPassword($string){
    if(!str_contains($_SESSION['password'],"ERROR")){
        $string = "USER MESSAGE: ". $_SESSION['password'];
        return true;
    }    else{
        $string = "USER MESSAGE: ". $_SESSION['password'];
        return false;
    }
}

function get_staff($conn){
    $sql = "SELECT staffid, job, fname, lname, email, pwd FROM staff where job != ? ORDER BY job DESC";

    $stmt = $conn->prepare($sql);
    $exclude_job = "adm";

    $stmt->bindParam(1, $exclude_job);

    $stmt->execute();
    $result = $stmt->fetchAll(PDO::FETCH_ASSOC);  // it fetch everything that maches
    $conn = null;
    return $result;
}