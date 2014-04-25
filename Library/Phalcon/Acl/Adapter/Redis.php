<?php
namespace Phalcon\Acl\Adapter;

use Phalcon\Acl\Adapter;
use Phalcon\Acl\AdapterInterface;
use Phalcon\Acl\Exception;
use Phalcon\Acl;
use Phalcon\Acl\Resource;
use Phalcon\Acl\ResourceInterface;
use Phalcon\Acl\Role;
use Phalcon\Acl\RoleInterface;

/**
 * Class Redis
 * @package Phalcon\Acl\Adapter
 */
class Redis extends Adapter implements AdapterInterface
{

    const ROLE_TPL = '%s:role:%s';
    const RESOURCE_TPL = '%s:resource:%s';
    const RESOURCE_ACCESS_SET_TPL = '%s:resource_access:%s';

    const ROLES_SET = '%s:roles';
    const RESOURCES_SET = '%s:resources';

    const ACCESS_LIST_INCR_KEY = '%s:access_list:incr';
    const ACCESS_LIST_HASH_KEY_TPL = '%s:access_list:%d';
    const ACCESS_LIST_SET_ROLE_INDEX = '%s:index:role:%s';
    const ACCESS_LIST_SET_RESOURCE_INDEX = '%s:index:resource:%s';
    const ACCESS_LIST_SET_ACCESS_INDEX = '%s:index:access:%s';

    const INHERITED_ROLES_SET = '%s:inherited:%s';

    /**
     * @var \Redis
     */
    private $redis;
    private $namespace;

    public function __construct(\Redis $redis, $namespace = 'acl')
    {
        $this->redis = $redis;
        $this->namespace = $namespace;
    }

    /**
     * @param string $roleName
     * @return bool
     */
    public function isRole($roleName)
    {
        return $this->redis->exists(sprintf(self::ROLE_TPL, $this->namespace, $roleName));
    }

    /**
     * @param string $resourceName
     * @param string|array $accessList
     * @throws Exception
     * @return bool
     */
    public function addResourceAccess($resourceName, $accessList)
    {
        if (!$this->isResource($resourceName)) {
            throw new Exception("Resource '" . $resourceName . "' does not exist in ACL");
        }

        if (is_array($accessList)) {
            foreach($accessList as $accessListName) {
                $this->redis->sAdd(sprintf(self::RESOURCE_ACCESS_SET_TPL, $this->namespace, $resourceName), $accessListName);
            }
        } else {
            $this->redis->sAdd(sprintf(self::RESOURCE_ACCESS_SET_TPL, $this->namespace, $resourceName), $accessList);
        }

        return true;
    }

    /**
     * @param string $roleName
     * @param string $resourceName
     * @param mixed $accessName
     * @return bool
     */
    public function allow($roleName, $resourceName, $accessName)
    {
        $this->allowOrDeny($roleName, $resourceName, $accessName, Acl::ALLOW);

        return true;
    }

    /**
     * @param string $roleName
     * @param string $roleToInherit
     * @throws Exception
     */
    public function addInherit($roleName, $roleToInherit)
    {

        if (!$this->redis->exists(sprintf(self::ROLE_TPL, $this->namespace, $roleToInherit))) {
            throw new Exception("Role '" . $roleToInherit . "' does not exist in the role list");
        }

        $this->redis->sAdd(sprintf(self::INHERITED_ROLES_SET, $this->namespace, $roleName), $roleToInherit);
    }

    /**
     * @param string $resourceName
     * @return bool
     */
    public function isResource($resourceName)
    {
        return $this->redis->exists(sprintf(self::RESOURCE_TPL, $this->namespace, $resourceName));
    }

    /**
     * @param string $role
     * @param string $resource
     * @param string $access
     * @return bool
     */
    public function isAllowed($role, $resource, $access)
    {

        if ($index = $this->getIndex($role, $resource, $access)) {
            return (bool)$this->redis->hGet(sprintf(self::ACCESS_LIST_HASH_KEY_TPL, $this->namespace, $index), 'isAllowed');
        }

        $inheritedRoles = $this->redis->sMembers(sprintf(self::INHERITED_ROLES_SET, $this->namespace, $role));

        foreach ($inheritedRoles as $role) {
            if ($index = $this->getIndex($role, $resource, $access)) {
                return (bool)$this->redis->hGet(sprintf(self::ACCESS_LIST_HASH_KEY_TPL, $this->namespace, $index), 'isAllowed');
            }
        }

        if ($index = $this->getIndex($role, $resource, '*')) {
            return (bool)$this->redis->hGet(sprintf(self::ACCESS_LIST_HASH_KEY_TPL, $this->namespace, $index), 'isAllowed');
        }

        foreach ($inheritedRoles as $role) {
            if ($index = $this->getIndex($role, $resource, '*')) {
                return (bool)$this->redis->hGet(sprintf(self::ACCESS_LIST_HASH_KEY_TPL, $this->namespace, $index), 'isAllowed');
            }
        }

        if ($index = $this->getIndex($role, '*', $access)) {
            return (bool)$this->redis->hGet(sprintf(self::ACCESS_LIST_HASH_KEY_TPL, $this->namespace, $index), 'isAllowed');
        }

        return (bool)$this->_defaultAccess;
    }

    /**
     * Adds a role to the ACL list. Second parameter lets to inherit access data from other existing role
     *
     * @param  RoleInterface $role
     * @param  array|string $accessInherits
     * @return boolean
     */
    public function addRole($role, $accessInherits = null)
    {

        if (!is_object($role)) {
            $role = new Role($role);
        }

        if (!$this->redis->exists(sprintf(self::ROLE_TPL, $this->namespace, $role->getName()))) {
            $this->redis->set(sprintf(self::ROLE_TPL, $role->getName()), $this->namespace, $role->getDescription());
            $this->updateAccessList($role->getName(), '*', '*', $this->_defaultAccess);
            $this->redis->sAdd(sprintf(self::ROLES_SET, $this->namespace), $role->getName());
        }

        if ($accessInherits) {
            if (is_array($accessInherits)) {
                foreach ($accessInherits as $accessInherit) {
                    $this->addInherit($role->getName(), $accessInherit);
                }
            } else {
                $this->addInherit($role->getName(), $accessInherits);
            }
        }

        return true;
    }

    /**
     * @return ResourceInterface[]
     */
    public function getResources()
    {
        $arrOfResources = $this->redis->sMembers(sprintf(self::RESOURCES_SET, $this->namespace));
        $aRet = [];

        foreach ($arrOfResources as $resourceName) {
            $Resource = new Resource(
                $resourceName,
                $this->redis->get(sprintf(self::RESOURCE_TPL, $this->namespace, $resourceName))
            );

            array_push($aRet, $Resource);
        }

        return $aRet;
    }

    /**
     * @param string $roleName
     * @param string $resourceName
     * @param mixed $accessName
     * @return bool
     */
    public function deny($roleName, $resourceName, $accessName)
    {
        $this->allowOrDeny($roleName, $resourceName, $accessName, Acl::DENY);

        return true;
    }

    /**
     * @return RoleInterface[]
     */
    public function getRoles()
    {
        $arrOfRoles = $this->redis->sMembers(sprintf(self::ROLES_SET, $this->namespace));
        $aRet = [];

        foreach ($arrOfRoles as $roleName) {
            $Role = new Resource(
                $roleName,
                $this->redis->get(sprintf(self::RESOURCE_TPL, $this->namespace, $roleName))
            );

            array_push($aRet, $Role);
        }

        return $aRet;
    }

    /**
     * Adds a resource to the ACL list
     *
     * Access names can be a particular action, by example
     * search, update, delete, etc or a list of them
     *
     * @param   ResourceInterface $resource
     * @param   array $accessList
     * @return  boolean
     */
    public function addResource($resource, $accessList=null)
    {
        if (!is_object($resource)) {
            $resource = new Resource($resource);
        }

        if (!$this->redis->exists(sprintf(self::RESOURCE_TPL, $this->namespace, $resource->getName()))) {
            $this->redis->set(sprintf(self::RESOURCE_TPL, $this->namespace, $resource->getName()), $resource->getDescription());
            $this->redis->sAdd(sprintf(self::RESOURCES_SET, $this->namespace), $resource->getName());
        }

        if ($accessList) {
            return $this->addResourceAccess($resource->getName(), $accessList);
        }

        return true;
    }

    public function dropResourceAccess($resourceName, $accessList)
    {
//        TODO
    }

    /**
     * Inserts/Updates a permission in the access list
     *
     * @param  string                 $roleName
     * @param  string                 $resourceName
     * @param  string                 $access
     * @param  integer                $action
     * @throws Exception
     */
    protected function allowOrDeny($roleName, $resourceName, $access, $action)
    {
        if (!$this->isRole($roleName)) {
            throw new Exception('Role "' . $roleName . '" does not exist in the list');
        }

        if (is_array($access)) {
            foreach ($access as $accessName) {
                $this->insertOrUpdateAccess($roleName, $resourceName, $accessName, $action);
            }
        } else {
            $this->insertOrUpdateAccess($roleName, $resourceName, $access, $action);
        }
    }

    /**
     * @param $roleName
     * @param $resourceName
     * @param $accessName
     * @param $action
     * @throws Exception
     */
    protected function insertOrUpdateAccess($roleName, $resourceName, $accessName, $action)
    {
        $key = sprintf(self::RESOURCE_ACCESS_SET_TPL, $resourceName);

        if (!$this->redis->exists($key)) {
            throw new Exception(
                "Access '" . $accessName . "' does not exist in resource '" . $resourceName . "' in ACL"
            );
        }

        if (!$this->redis->sIsMember($key, $accessName)) {
            throw new Exception(
                "Access '" . $accessName . "' does not exist in resource '" . $resourceName . "' in ACL"
            );
        }

        $this->updateAccessList($roleName, $resourceName, $accessName, $action);

        /**
         * Update the access '*' in access_list
         */

        $exists = $this->redis->sInter(
            sprintf(self::ACCESS_LIST_SET_ROLE_INDEX, $roleName),
            sprintf(self::ACCESS_LIST_SET_RESOURCE_INDEX, $resourceName),
            sprintf(self::ACCESS_LIST_SET_ACCESS_INDEX, '*')
        );

        if (empty($exists)) {
            $this->updateAccessList($roleName, $resourceName, '*', $this->_defaultAccess);
        }
    }

    /**
     * @param $roleName
     * @param $resourceName
     * @param $accessName
     * @param $isAllowed
     */
    protected function updateAccessList($roleName,$resourceName, $accessName, $isAllowed)
    {

        if (!$id = $this->getIndex($roleName, $resourceName, $accessName)) {
            $id = $this->redis->incr(sprintf(self::ACCESS_LIST_INCR_KEY, $this->namespace));
        }

        $this->redis->hMset(sprintf(self::ACCESS_LIST_HASH_KEY_TPL, $id), [
            'role' => $roleName,
            'resource' => $resourceName,
            'access'   => $accessName,
            'isAllowed' => $isAllowed
        ]);

        $this->redis->sAdd(sprintf(self::ACCESS_LIST_SET_ROLE_INDEX, $roleName), $id);
        $this->redis->sAdd(sprintf(self::ACCESS_LIST_SET_RESOURCE_INDEX, $resourceName), $id);
        $this->redis->sAdd(sprintf(self::ACCESS_LIST_SET_ACCESS_INDEX, $accessName), $id);

    }

    /**
     * @param $roleName
     * @param $resourceName
     * @param $accessName
     * @throws \RuntimeException
     * @return int|bool
     */
    protected function getIndex($roleName, $resourceName, $accessName)
    {
        $ai = $this->redis->sInter(
            sprintf(self::ACCESS_LIST_SET_ROLE_INDEX, $roleName),
            sprintf(self::ACCESS_LIST_SET_RESOURCE_INDEX, $resourceName),
            sprintf(self::ACCESS_LIST_SET_ACCESS_INDEX, $accessName)
        );

        return $ai[0];
    }
} 