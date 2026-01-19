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
           audititor(dabco_insert(),only_patients(dabco_select(), $_POST['patid']),"bok", "New booking registered" );

           $_SESSION['usermessage'] = "Your book has been committed!";
           header('Location: book.php');
           exit();
       }else{
           $_SESSION['usermessage'] = "Error booking has failed!";
           header('Location: book.php');
           exit();
       }

    }
    catch(PDOException $e){
        $_SESSION["usermessage"] = "Error: " . $e->getMessage();
        header('Location: book.php');
        exit();
    } catch(Exception $e){
        $_SESSION["usermessage"] = "Error: " . $e->getMessage();
        header('Location: book.php');
        exit();
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

echo "<form action='' method='post'>"; // Form posts back to the same page
$staff = get_staff(dabco_select());

echo"<label for='apt_time'>Appointment Time: </label> ";
echo"<input type='time' name='apt_time' required>";

echo "<br>";

echo"<label for='apt_date'>Appointment Date: </label>";
echo"<input type='date' name='apt_date' required>";

echo "<br>";

echo "<select name='staff'>";

foreach ($staff as $staf) {

    if($staf['job']="Doc"){
        $role = "Doctor";
    } elseif ($staf['job']='Nur'){
        $role = "Nurse";
    }
    echo "<option value='".$staf['staff_id']."'>".$role." ".$staf['fname']." ".$staf['lname']." Room ".$staf['rom']."</option>";
}
echo"</select>";
echo "<br>";

// Submit button is missing — should be added to make the form work
echo "<input type='submit' placeholder='Register'>";

echo "</form>";
echo "</div>";


echo "</body>";
echo "</html>";
?>



