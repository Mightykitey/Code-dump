<?php

session_start(); // Start the session for this page to allow session variables (like flash messages)


// Include required PHP files only once
require_once "assets/commonfunk.php"; // Common utility functions
require_once "assets/dabco.php";      // Database connection functions

if(!isset($_SESSION["patid"])){
    $_SESSION['usermessage'] = "Error: You are not logged in.";
    header("Location: login.php");
    exit;
}

// Check if the form was submitted using the POST method

// Output the HTML document
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

echo "<h2>Your Booking</h2>";

Echo user_message();

$prof = pro_getter(dabco_select());
if (!$prof){
    echo"no prof found";
}else{

    echo "<table id='booking'>";

    foreach($prof as $pro){
        if($pro['code']="reg"){
            $role = 'Registered';
        }else if ($apt['role']="log"){}
        $role = "Login";
    }

    echo "<form action='' method='post'>";

    echo "<tr>";
    echo "<td>Date:   ".date('M d, Y @ h:i A',$apt['appdate'])."</td>";
    echo "<td>Made on:    ".date('M d, Y @ h:i A',$apt['bookdon']) . "</td>";
    echo "<td>With:    ".$role. " ".$apt['fname']." ".$apt['lname']." ". "</td>";
    echo "<td>In: ".$apt['rom']."</td>";
    echo "<td><input type='hidden' name='aptid' value=".$apt['booking_id'].">
    <input type='submit' name='appdelete' value='Cancel Apt'/>
    <input type='submit' name='appdchange' value='Change Apt'/></td>";

    echo "</tr>";
    echo "</form>"; // creaating a for each table
}

echo "</table>";

echo "</div>";

echo "</body>";
echo "</html>";
?>
