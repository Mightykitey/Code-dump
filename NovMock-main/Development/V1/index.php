<?php
session_start();

require_once "assets/commonfunk.php";
require_once "assets/dabco.php";

echo "<!DOCTYPE html>";

echo "<html>";

echo "<head>";
echo"<title>Rolsa Technologies</title>";
echo"<link href='css/styless.css' rel='stylesheet'>";
require_once "assets/header.php";
echo "</head>";
echo "<bod>";

echo "<p>Solar panels work by converting sunlight into electricity, 
allowing you to power your home with clean, renewable energy. 
By generating your own electricity, you reduce the amount you need to buy from the grid,
 which can cut your bills by 30–70% depending on your usage and system size. 
 Any extra energy can be stored in a battery or sold back to the grid, 
 giving you further savings or even income. Over time, 
 solar panels usually pay for themselves within about a decade, 
 while continuing to provide free energy for 25 years or more.</p>";

echo "<img src='images/Solar panel.jpg' alt='solar panel'>";

echo"</body>";
require_once "assets/footer.php";
echo"</html>";
