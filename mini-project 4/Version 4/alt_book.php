<?php

session_start();

require_once "assets/commonfunk.php";
require_once "assets/staff_com.php";
require_once "assets/dabco.php";


if (!isset($_SESSION['patid'])) {
    $_SESSION['usermessage'] = "ERROR: You are not logged in!";
    header("Location: login.php");
    exit;
} elseif($_SERVER["REQUEST_METHOD"] === "POST"){
    $tmp = $_POST['apt_date']. ' '.$_POST['apt_time'];
    $epoch = strtotime($tmp);
    if (apt_update(dabco_insert(),$_SESSION['aptid'],$epoch)){
        $_SESSION['usermessage'] = "SUCCESS: Your appointment updated successfully!";
        unset($_SESSION['aptid']);
        book_audititor(dabco_insert(),apt_update(dabco_insert(),$_POST['email']), "abk", "Updated Booking");
        header("Location: book.php");
        exit;
    }else{
        $_SESSION['usermessage'] = "ERROR: appointment failed to update";
        unset($_SESSION['aptid']);
        header("Location: book.php");
        exit;
    }
}


echo "<!doctype html>";
echo "<html>";

echo "<head>";
echo "<title>Booking</title>"; // Page title
echo "<link href='css/styles.css' rel='stylesheet'>"; // Link to external CSS
echo"<img src='images/primary_oaks_surgery.jpg' alt='primary oaks surgery'>";
echo "</head>";

echo "<body>";

echo "<div id='main'>"; // Main container
echo "<h1>Primary Oaks Surgery</h1>"; // Page heading
require_once "assets/nav.php"; // Include navigation menu
echo "</div>";

// Content area with the registration form
echo "<div class='content'>";

echo "<br>";
echo user_message();

$apt =apt_fetch(dabco_select(),$_SESSION["aptid"]);

echo "<form action='' method='post'>"; // Form posts back to the same page

$staff = get_staff(dabco_select());

$apt_time = date('H:i:S', $apt['appdate']);
$apt_date = date('Y-m-d', $apt['bookdon']);


echo"<label for='apt_time'>Appointment Time: </label> ";
echo"<input type='time' name='apt_time' value='". $apt_time. "' required>";

echo "<br>";

echo"<label for='apt_date'>Appointment Date: </label>";
echo"<input type='date' name='apt_date' value='".$apt_date."' required>";

echo "<br>";

echo "<select name='staff'>";

foreach ($staff as $staf) {

    if($staf['job']="Doc"){
        $role = "Doctor";
    } elseif ($staf['job']='Nur'){
        $role = "Nurse";
    }
    if($apt['staff_id'] == $staf['staff_id']){
        $selected = "selected";
    }else{
        $selected = "";
    }
    echo "<option value=".$staf['staff_id']." ".$selected. ">".$role." ".$staf['fname']." ".$staf['lname']." Room ".$staf['rom']."</option>";
}
echo"</select>";
echo "<br>";

// Submit button is missing — should be added to make the form work
echo "<input type='submit' value='Update Appointment' placeholder='Register'>";

echo "</form>";
echo "</div>";


echo "</body>";
echo "</html>";
?>





