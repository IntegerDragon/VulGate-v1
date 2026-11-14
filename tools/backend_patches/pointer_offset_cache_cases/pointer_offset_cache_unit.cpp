// Standalone public-API regression for CBMC 6.11.0. No solver is invoked.
#include <goto-symex/simplify_expr_with_value_set.h>
#include <pointer-analysis/value_set.h>
#include <util/arith_tools.h>
#include <util/config.h>
#include <util/namespace.h>
#include <util/pointer_expr.h>
#include <util/ssa_expr.h>
#include <util/symbol_table.h>

#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

static unsigned checks = 0;

static void require(bool condition, const std::string &message)
{
  if(!condition)
    throw std::runtime_error(message);
}

static exprt pack(exprt::operandst operands)
{
  struct_typet type;
  for(std::size_t i = 0; i < operands.size(); ++i)
    type.components().emplace_back("field" + std::to_string(i), operands[i].type());
  return struct_exprt(std::move(operands), std::move(type));
}

// The base-class reference also checks virtual dispatch to the reset boundary.
static void check(
  simplify_exprt &simplifier,
  exprt input,
  const exprt &expected,
  const std::string &name)
{
  simplifier.simplify(input);
  if(input != expected)
  {
    std::cerr << "Actual:\n" << input.pretty() << "\nExpected:\n"
              << expected.pretty() << '\n';
    throw std::runtime_error(name);
  }
  ++checks;
  std::cout << "PASS " << name << '\n';
}

struct fixturet
{
  symbol_tablet symbols;
  namespacet ns{symbols};
  value_sett values;
  const unsignedbv_typet byte_type{8};
  const signedbv_typet offset_type{64};
  pointer_typet pointer_type;
  symbol_exprt original_pointer;
  symbol_exprt object_a{"object_a", byte_type};
  symbol_exprt object_b{"object_b", byte_type};
  ssa_exprt pointer;

  explicit fixturet(unsigned pointer_width)
    : pointer_type(byte_type, pointer_width),
      original_pointer("pointer", pointer_type),
      pointer(original_pointer)
  {
    for(const auto &symbol : {original_pointer, object_a, object_b})
      require(!symbols.add(symbolt(symbol.identifier(), symbol.type(), ID_C)),
              "fixture symbol insertion");
    pointer.set_level_0(0);
    pointer.set_level_1(0);
    pointer.set_level_2(1);
  }

  void store(const ssa_exprt &target, const value_sett::object_mapt &objects)
  {
    const auto l1 = remove_level_2(target);
    values.update_entry(
      value_sett::entryt{l1.identifier(), ""}, l1.type(), objects, false);
  }

  void set_offsets(
    const ssa_exprt &target,
    const std::vector<std::pair<exprt, int>> &offsets)
  {
    value_sett::object_mapt objects;
    for(const auto &entry : offsets)
      values.insert(objects, entry.first, from_integer(entry.second, offset_type));
    store(target, objects);
  }

  exprt repeated_offsets(const typet &type) const
  {
    auto another_l2 = pointer;
    another_l2.set_level_2(9);
    return pack({pointer_offset_exprt(pointer, type),
                 pointer_offset_exprt(another_l2, type),
                 pointer_offset_exprt(pointer, type)});
  }

  exprt repeated_value(int value, const typet &type) const
  {
    const auto constant = from_integer(value, type);
    return pack({constant, constant, constant});
  }
};

static void run(unsigned pointer_width)
{
  config.ansi_c.set_LP64();
  config.ansi_c.pointer_width = pointer_width;
  fixturet f(pointer_width);
  simplify_expr_with_value_sett simplifier(f.values, ID_C, f.ns);
  const auto name = [pointer_width](const std::string &text) {
    return std::to_string(pointer_width) + "-bit " + text;
  };

  f.set_offsets(f.pointer, {{f.object_a, 300}, {f.object_b, 300}});
  require(f.values.get_value_set(remove_level_2(f.pointer), f.ns).size() == 2,
          "uniform fixture contains two objects");
  check(simplifier, f.repeated_offsets(f.offset_type),
        f.repeated_value(300, f.offset_type), name("uniform offsets and L2 reuse"));

  const unsignedbv_typet narrow{8};
  const signedbv_typet medium{16};
  check(simplifier,
        pack({pointer_offset_exprt(f.pointer, narrow),
              pointer_offset_exprt(f.pointer, medium),
              pointer_offset_exprt(f.pointer, f.offset_type)}),
        pack({from_integer(300, narrow), from_integer(300, medium),
              from_integer(300, f.offset_type)}),
        name("same L1 with distinct result types"));

  f.set_offsets(f.pointer, {{f.object_a, -3}, {f.object_b, -3}});
  check(simplifier, f.repeated_offsets(f.offset_type),
        f.repeated_value(-3, f.offset_type), name("negative numeric offset"));

  f.set_offsets(f.pointer, {{f.object_a, 1}, {f.object_b, 4}});
  auto unchanged = f.repeated_offsets(f.offset_type);
  check(simplifier, unchanged, unchanged, name("nonuniform offset fallback"));

  f.values.assign(remove_level_2(f.pointer), exprt(ID_unknown, f.pointer_type),
                  f.ns, false, false);
  check(simplifier, unchanged, unchanged, name("unknown candidate fallback"));

  value_sett::object_mapt invalid;
  f.values.insert(invalid, exprt(ID_invalid, f.pointer_type));
  f.store(f.pointer, invalid);
  const auto invalid_values =
    f.values.get_value_set(remove_level_2(f.pointer), f.ns);
  require(invalid_values.size() == 1 && invalid_values.front().id() == ID_invalid,
          "invalid fixture preserves invalid instead of normalizing to unknown");
  check(simplifier, unchanged, unchanged, name("invalid candidate fallback"));

  auto failed_type = f.byte_type;
  failed_type.set(ID_C_is_failed_symbol, true);
  const symbol_exprt failed_object("failed_object", failed_type);
  require(!f.symbols.add(symbolt("failed_object", failed_type, ID_C)),
          "failed symbol insertion");
  f.set_offsets(f.pointer, {{failed_object, 2}});
  check(simplifier, unchanged, unchanged, name("failed object fallback"));

  value_sett::object_mapt unknown_offset;
  f.values.insert(unknown_offset, f.object_a);
  f.store(f.pointer, unknown_offset);
  check(simplifier, unchanged, unchanged, name("unknown offset fallback"));

  f.store(f.pointer, value_sett::object_mapt{});
  require(f.values.get_value_set(remove_level_2(f.pointer), f.ns).empty(),
          "empty fixture contains no candidates");
  check(simplifier, unchanged, unchanged, name("empty value set fallback"));

  // One simplifier is retained for every call above and below. These updates
  // check both negative-to-positive and positive-to-positive invalidation.
  f.set_offsets(f.pointer, {{f.object_a, 7}});
  check(simplifier, f.repeated_offsets(f.offset_type),
        f.repeated_value(7, f.offset_type), name("negative cache invalidated"));
  f.set_offsets(f.pointer, {{f.object_a, 23}});
  check(simplifier, f.repeated_offsets(f.offset_type),
        f.repeated_value(23, f.offset_type), name("positive cache invalidated"));

  auto another_frame = f.pointer;
  another_frame.set_level_1(1);
  auto another_thread = f.pointer;
  another_thread.set_level_0(1);
  f.set_offsets(f.pointer, {{f.object_a, 1}});
  f.set_offsets(another_frame, {{f.object_a, 4}});
  f.set_offsets(another_thread, {{f.object_a, 7}});
  check(simplifier,
        pack({pointer_offset_exprt(f.pointer, f.offset_type),
              pointer_offset_exprt(another_frame, f.offset_type),
              pointer_offset_exprt(another_thread, f.offset_type),
              pointer_offset_exprt(f.pointer, f.offset_type)}),
        pack({from_integer(1, f.offset_type), from_integer(4, f.offset_type),
              from_integer(7, f.offset_type), from_integer(1, f.offset_type)}),
        name("L0 thread and L1 frame identities stay distinct"));
}

static void direct_node_update()
{
  config.ansi_c.set_LP64();
  fixturet f(64);
  f.set_offsets(f.pointer, {{f.object_a, 3}});
  simplify_expr_with_value_sett simplifier(f.values, ID_C, f.ns);
  const pointer_offset_exprt input(f.pointer, f.offset_type);
  const auto first = simplifier.simplify_pointer_offset(input);
  require(first.expr == from_integer(3, f.offset_type), "first direct node call");
  f.set_offsets(f.pointer, {{f.object_a, 7}});
  const auto second = simplifier.simplify_pointer_offset(input);
  if(second.expr != from_integer(7, f.offset_type))
    std::cerr << "Direct call after update returned:\n" << second.expr.pretty()
              << "\nExpected offset 7\n";
  require(second.expr == from_integer(7, f.offset_type),
          "direct public node call observes updated value set");
  ++checks;
  std::cout << "PASS direct public node call observes updated value set\n";
}

int main(int argc, char **argv)
{
  try
  {
    if(argc == 2 && std::string(argv[1]) == "--direct-node-update")
    {
      direct_node_update();
      return 0;
    }
    run(32);
    run(64);
    direct_node_update();
    std::cout << "TOTAL " << checks << " PASS\n";
    return 0;
  }
  catch(const std::exception &error)
  {
    std::cerr << "FAIL " << error.what() << '\n';
    return 1;
  }
}
