<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>主页面</title>
</head>
<body>
<div>
    <#if (loginUser)??>用户名：${loginUser.username}</#if>
    <!-- 退出系统 -->
    <a href="/doLogout">退出</a>
</div>
<h3>
    主页面
</h3>
<div>
    <table>
        <tr>
            <td>URL-无权限测试</td>
            <td>
                <a href="/noPower/test" target="_blank">noPower test</a>
            </td>
        </tr>
        <tr>
            <td>URL-有角色测试</td>
            <td>
                <a href="/admin/test" target="_blank">admin list</a><br>
            </td>
        </tr>
        <tr>
            <td>URL-有权限测试</td>
            <td>
                <a href="/user/list" target="_blank">user list</a>
                <a href="/user/test" target="_blank">user test</a>
            </td>
        </tr>
        <tr>
            <td>URL-自定义权限校验</td>
            <td>
                <a href="/api/test" target="_blank">api list</a>
            </td>
        </tr>
        <tr>
            <td>方法-权限判断</td>
            <td>
                <a href="/department/list" target="_blank">department list</a>
            </td>
        </tr>
        <tr>
            <td>API-权限、角色测试</td>
            <td>
                <a href="/admin/apiPower" target="_blank">admin apiPower</a><br>
            </td>
        </tr>
    </table>
</div>
</body>
</html>