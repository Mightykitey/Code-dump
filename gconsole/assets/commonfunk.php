<?php

function new_console($conn, $post)
{
    try {
        $sql = "INSERT INTO console (Manufacturer, C_name, Release_date, Controller_no, Bit) VALUES (?,?,?,?,?)"; //we are doing a prepared statement
        $stmt = $conn->prepare($sql);  //prepare to sql

        $stmt->bindParam(1, $post['Manufacturer']); //bind parameters for security
        $stmt->bindParam(2, $post['name']); // binding the data from my form. which make it more secured from a sql infections
        $stmt->bindParam(3, $post['date']);
        $stmt->bindParam(4, $post['controller']);
        $stmt->bindParam(5, $post['bit']);

        $stmt->execute(); //run the query to insert
        $conn = null; // closes the connection so cant be abused
    } catch (PDOException $e) {
        error_log('Console datebase error: ' . $e->getMessage());
        throw new Exception('Console database error' . $e);
    } catch (Exception $e) {
        error_log('Console error: ' . $e->getMessage());
        throw new Exception('Console database error' . $e->getMessage());
    }
}
function user_message()
    {
        if (isset($_SESSION['usermessage'])) {
            $message = "<p>" . $_SESSION['usermessage'] . "</p>";
            unset($_SESSION['usermessage']);
            return $message;
        } else {
            return "";
        }
}


//check to make sure that usernames are unique, if the same name exists. you may not use.
function only_user($conn,$username){
    try{
        $sql = "SELECT username FROM user WHERE username = ?"; //set up the sql statement
        $stmt = $conn->prepare($sql);   //prepares
        $stmt->bindparam(1, $username);
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


function reg_user($conn, $post){
    try{
        $sql = "INSERT INTO user (Username, password, Signupdate, Dateofbirth, Country) VALUES (?,?,?,?,?)";
        $stmt = $conn->prepare($sql);

        $stmt->bindParam(1, $post['username']);
        $hpswd= password_hash($post['password'], PASSWORD_DEFAULT);
        $stmt->bindParam(2, $hpswd);
        $stmt->bindParam(3, $post['date']);
        $stmt->bindParam(4, $post['birth']);
        $stmt->bindParam(5, $post['country']);

        $stmt->execute();
        $conn = null;
        return true;


    }catch(PDOException|Exception $e){
        error_log("There an error in the user table: " . $e->getMessage());
        throw new Exception('There is an error in the user table' . $e);
    }
}

function login($conn, $post){
    try{
        $sql = "SELECT * FROM user WHERE username = ?"; //set up the sql statement. * get all the fields form teh user
        $stmt = $conn->prepare($sql);

        $stmt->bindParam(1, $post['username']); // binds the parameters to executes to be more secure
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC); // brings back the results
        $conn = null;

        if($result){
            return $result;
        }else{
            $_SESSION["usermessage"] = 'USER NOT FOUND';
            header("location: index.php");
            exit();
        }


    }catch(Exception $e){
        $_SESSION["usermessage"] = 'User login'.$e->getMessage();
        header("location: index.php");
        exit();
    }

}