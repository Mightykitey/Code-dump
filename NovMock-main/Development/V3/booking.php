<?php

session_start();

require_once "assets/commonfunk.php";
require_once "assets/staff_com.php";
require_once "assets/dabco.php";

if ($_SERVER["REQUEST_METHOD"] === "POST") { // on any page this block of code should be here so  if anywhere else the redirect can go wrong

    try {
        $stmp = $_POST['apt_date'] . ' ' . $_POST['apt_time'];
        $epoch = strtotime($stmp);
        if(commit_bookimg(dabco_insert(),$epoch)){
            audititor(dabco_insert(),only_user(dabco_select(), $_POST['usrid']),"bok", "New booking registered" );

            $_SESSION['usermessage'] = "Your book has been committed!";
            header('Location: apt.php');
            exit();
        }else{
            $_SESSION['usermessage'] = "Error booking has failed!";
            header('Location: booking.php');
            exit();
        }
    }
    catch(PDOException $e){
        $_SESSION["usermessage"] = "Error: " . $e->getMessage();
        header('Location: booking.php');
        exit();
    } catch(Exception $e){
        $_SESSION["usermessage"] = "Error: " . $e->getMessage();
        header('Location: booking.php');
        exit();
    }
}

echo "<!DOCTYPE html>";

echo "<html>";

echo "<head>";
echo "<title>Rolsa Technologies</title>";

require_once "assets/header.php";
echo "</head>";

// Content area with the registration form
echo "<div class='container'>";
echo "<form method='post' action=''>"; // Form posts back to the same page
echo "<br>";

$staff = get_staff(dabco_select());

echo"<label for='apt_time'>Appointment Time: </label> ";
echo"<input type='time' name='apt_time' required>";

echo "<br>";

echo"<label for='apt_date'>Appointment Date: </label>";
echo"<input type='date' name='apt_date' required>";

echo "<br>";

echo "<select name='staff'>";#

foreach ($staff as $staf) {

    if($staf['job']="ins"){
        $role = "Inspector";
    } elseif ($staf['job']='egr'){
        $role = "Engineer";
    }
    echo "<option value='".$staf['staffid']." ".$role." ".$staf['fname']." ".$staf['lname']."</option>";
}

echo"</select>";
echo "<br>";

echo"<input id='submit' type='submit' placeholder='Register'>";
echo "</form>";
echo "</div>";

require_once "assets/footer.php";
echo user_message();
echo "</body>";
echo "</html>";
