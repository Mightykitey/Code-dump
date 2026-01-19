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






require_once "assets/footer.php";
echo user_message();
echo"</body>";
echo"</html>";

