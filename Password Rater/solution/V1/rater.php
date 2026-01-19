<?php

session_start();/*each page that needs a session, not file*/

echo "<!DOCTYPE html>";
echo "<html>";
echo "<head>";

echo "</head>";


echo "<body>";
echo"<h1>Password Rat3r1!</h1>";
require_once 'assets/nav.php';
echo"<br>";
echo"<br>";

echo usr_msg();

echo "<form method='post' action=''>"; // request(post)
// is there is not sent it just reload the page
echo "<label for='Pw'>Please enter our password to be rated</label>";
echo"<br>";
// this a label in front of the box's
echo "<input type='text' name='password' id='Pw' placeholder='Password'>";
// most thing start with an input. declare a name(num). placeholder text in the box's
echo"<br>";
echo "<br>";
echo "<label for='lgn'> Login in </label>";
echo"<br>";
echo "<input  type='submit' name='submit' id='lgn' value='login'>";




echo "</form>";


echo "<link rel='stylesheet' href='css/styles.css'>";

echo "</table>";
echo "</body>";
echo "</html>";
