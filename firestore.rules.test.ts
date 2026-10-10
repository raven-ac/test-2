/**
 * RAVEN Firestore Security Rules Test Suite
 * Validates Dirty Dozen payload rejections & authorized role gates.
 */

export const DIRTY_DOZEN_TEST_CASES = [
  {
    name: "Payload 1: Customer sets role to 'admin' on registration",
    targetPath: "users/attacker_uid",
    payload: { id: "attacker_uid", email: "evil@test.com", role: "admin" },
    expectedResult: "PERMISSION_DENIED"
  },
  {
    name: "Payload 2: User A writes to User B's profile",
    targetPath: "users/user_b",
    authUid: "user_a",
    payload: { id: "user_b", email: "userb@test.com", role: "customer" },
    expectedResult: "PERMISSION_DENIED"
  },
  {
    name: "Payload 3: Unverified email admin spoofing",
    authUid: "spoofed_uid",
    authEmail: "a.mdnuhad534@gmail.com",
    emailVerified: false,
    targetPath: "products/new_hoodie",
    payload: { id: "new_hoodie", name: "Hack", category: "tops", price: 0, stock: 10 },
    expectedResult: "PERMISSION_DENIED"
  },
  {
    name: "Payload 4: Creating order with mismatched victim userId",
    authUid: "user_a",
    targetPath: "orders/order_123",
    payload: { id: "order_123", userId: "victim_user_b", customerEmail: "victim@test.com", total: 120, status: "pending" },
    expectedResult: "PERMISSION_DENIED"
  },
  {
    name: "Payload 5: Customer updates status to delivered directly",
    authUid: "user_a",
    targetPath: "orders/order_123",
    payload: { status: "delivered" },
    expectedResult: "PERMISSION_DENIED"
  },
  {
    name: "Payload 6: User A attempts to read User B's shipping address",
    authUid: "user_a",
    targetPath: "users/user_b/addresses/addr_1",
    expectedResult: "PERMISSION_DENIED"
  },
  {
    name: "Payload 7: Denial of wallet invalid path ID",
    targetPath: "products/very_long_invalid_id_with_symbols!@#$%",
    expectedResult: "PERMISSION_DENIED"
  },
  {
    name: "Payload 8: Guest price manipulation on product",
    authUid: null,
    targetPath: "products/hoodie_01",
    payload: { price: 1 },
    expectedResult: "PERMISSION_DENIED"
  },
  {
    name: "Payload 9: Standard customer creating a product in catalog",
    authUid: "regular_customer_uid",
    targetPath: "products/hoodie_02",
    payload: { id: "hoodie_02", name: "Hoodie", category: "tops", price: 220, stock: 10 },
    expectedResult: "PERMISSION_DENIED"
  },
  {
    name: "Payload 10: Non-admin writing to admins collection",
    authUid: "regular_customer_uid",
    targetPath: "admins/regular_customer_uid",
    payload: { id: "regular_customer_uid", email: "attacker@test.com" },
    expectedResult: "PERMISSION_DENIED"
  },
  {
    name: "Payload 11: Blanket order listing without user scope filter",
    authUid: "regular_customer_uid",
    targetCollection: "orders",
    expectedResult: "PERMISSION_DENIED"
  },
  {
    name: "Payload 12: Injecting ghost field into user document",
    authUid: "user_a",
    targetPath: "users/user_a",
    payload: { id: "user_a", email: "a@test.com", role: "customer", maliciousGhostField: true },
    expectedResult: "PERMISSION_DENIED"
  }
];
