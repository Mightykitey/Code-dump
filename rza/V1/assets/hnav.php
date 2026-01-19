<?php

// Link to an external CSS stylesheet (Note: There is a mistake in the tag — see correction below)
echo "<link rel='stylesheet' href='css/styless.css'>";

// Start of navigation bar container
echo "<div class='navi'>"; // A div with class 'navi' for styling the navigation area

// Begin the navigation menu
echo "<nav>";

// Start of the unordered list for navigation links
echo "<ul>";

// Navigation item: Link to the registration page
echo "<li><a href='reg.php'>Registration</a></li>";

// Navigation item: Placeholder link for booking functionality
//echo "<li><a href='booking.php'>Bookings</a></li>";

// Navigation item: Placeholder link for booked appointments
//echo "<li><a href='apt.php'>appointments</a></li>";

// Navigation item: Placeholder link for login
echo "<li><a href='login.php'>Login</a></li>";


// End of the list
echo "</ul>";

// End of navigation
echo "</nav>";

// End of navigation container
echo "</div>";
