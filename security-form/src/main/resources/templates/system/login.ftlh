<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>登录页面</title>
    <!-- 引入静态资源 -->
    <link rel="stylesheet" type="text/css" href="css/login.css">
</head>
<body>
<#if error??>
    <div style="color: red;">${error}</div>
</#if>
<form action="/doLogin" method="post">
    <table>
        <tr>
            <td>用户名：</td>
            <td><input type="text" name="username" value="admin"></td>
        </tr>
        <tr>
            <td>密码：</td>
            <td><input type="text" name="password" value="123456"></td>
        </tr>
        <tr>
            <td><input type="submit" value="登录"></td>
        </tr>
    </table>
</form>
</body>
</html>