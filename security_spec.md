# RAVEN Security Specification & Rules Audit

## 1. Data Invariants
1. **User Identity Boundary**: A user profile at `/users/{userId}` can only be read or written by the authenticated user whose `request.auth.uid == userId` or a verified system admin.
2. **Anti-Escalation Gate**: A user cannot assign or update their own `role` property to `'admin'`. Normal user creations and updates must strictly enforce `role == 'customer'`. Admin privileges are determined exclusively via `exists(/databases/$(database)/documents/admins/$(request.auth.uid))` or the bootstrapped verified administrator email `a.mdnuhad534@gmail.com`.
3. **PII and Address Protection**: Subcollections under `/users/{userId}/addresses/{addressId}` and `/users/{userId}/wishlist/{productId}` can only be queried or mutated by the matching owner (`userId == request.auth.uid`) or admin.
4. **Order Integrity**: A customer creating an order at `/orders/{orderId}` must bind `incoming().userId == request.auth.uid`. A customer can only read their own orders (`resource.data.userId == request.auth.uid`). Once an order status reaches `'delivered'` or `'cancelled'` (terminal states), customers cannot modify it. Only admins can update order statuses.
5. **Catalog Immobility**: Public catalog garments `/products/{productId}` are readable by anyone (guests & members), but write/update/delete operations are strictly restricted to verified administrators.
6. **Path Hardening**: All target document IDs must satisfy alphanumeric/hyphen constraints `isValidId()`.

## 2. The Dirty Dozen Payloads (Designed to Fail)
1. **Payload 1 (Privilege Escalation on User Create)**: Unauthenticated or customer setting `role: "admin"` on `/users/{uid}`.
2. **Payload 2 (User Profile Shadow Overwrite)**: Authenticated user `userA` attempting to write to `/users/{userB}`.
3. **Payload 3 (Unverified Email Admin Spoofing)**: Attacker setting `email: "a.mdnuhad534@gmail.com"` with `email_verified: false` trying to write to `/products/{id}`.
4. **Payload 4 (Order Hijacking)**: Authenticated user creating an order with `userId: "another_victim_uid"`.
5. **Payload 5 (Order Status Tampering)**: Customer updating order status directly from `"pending"` to `"delivered"` or altering total amount.
6. **Payload 6 (PII Address Theft)**: User `userA` attempting to read `/users/{userB}/addresses/{addrId}`.
7. **Payload 7 (Denial-of-Wallet Long ID Attack)**: Writing to `/products/{overflow_id_with_2000_chars}`.
8. **Payload 8 (Product Price Manipulation by Guest)**: Unauthenticated client sending a `setDoc` or `updateDoc` to modify garment pricing.
9. **Payload 9 (Product Creation by Customer)**: Customer authenticated user attempting to create a product in `/products/{newId}`.
10. **Payload 10 (Admin Directory Tampering)**: Non-admin user attempting to insert themselves into `/admins/{my_uid}`.
11. **Payload 11 (Blanket Order Listing Scraping)**: Malicious client running an unscoped `getDocs(collection(db, 'orders'))` without a matching `where('userId', '==', auth.currentUser.uid)` filter.
12. **Payload 12 (Ghost Field Injection)**: Sending unexpected shadow fields `hackField: "exploit"` inside `/users/{userId}` beyond allowed schema keys.
