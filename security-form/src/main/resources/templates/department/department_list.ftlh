<#assign security=JspTaglibs["http://www.springframework.org/security/tags"] />
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>department_list</title>
</head>
<body>
    
    新增（按钮未加权限，后台加权限，用户有权限）：<a href="/department/add">新增按钮</a>
    <br>
    编辑（按钮未加权限，后台加权限，用户无权限）：<a href="/department/edit">编辑按钮</a>
    <br>
    删除（按钮未加权限，后台加自定义权限，用户有权限）：
    <a href="/department/delete">删除按钮</a>
    <br>
    
    test（按钮加权限，后台加权限，用户有权限）：
    <@security.authorize access="hasAuthority('department:test')">
        <a href="/department/test">test按钮</a>
    </@security.authorize>
    <!-- 通过有无角色判断 -->
    <#--
    <@security.authorize access="hasRole('admin')">
        <a href="/department/test">test按钮</a>
    </@security.authorize>
    -->

</body>
</html>